# fastssh

A fast SSH discovery and credential-testing orchestrator that favors existing
high-performance scanners and an async brute layer. It can ingest target lists
or masscan JSON, probe ports quickly, fan out async SSH login attempts with
strict concurrency, and optionally run post-compromise commands. Output is
structured and deduped for easy resumption.

## Features
- Async TCP probes to weed out dead hosts before brute attempts.
- Optional masscan JSON ingestion; reuse best-in-class scanning instead of
  hand-rolled loops.
- Credential expansion from user/password lists or combo files with dedupe.
- Concurrency controls (global and per-host) plus stop-after-first options.
- Structured results (JSONL) with banners/command output when requested.
- Minimal dependencies: `asyncssh` for SSH, `orjson` for fast logging.

## Quickstart
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python fastssh.py --targets targets.txt --users root admin --passwords root toor --max-workers 200
```

## Example: masscan → fastssh
```
masscan 0.0.0.0/0 -p22 --rate 10000 -oJ masscan.json
python fastssh.py --masscan-json masscan.json --users root --passwords root --stop-first-host
```

## CLI options (high level)
- Targets:
  - `--target` / `--targets`: inline host[:ports] entries or file, ports can be comma-separated per host.
  - `--masscan-json`: read targets from masscan JSON output.
  - `--targets-chunk N`: take only N entries from a targets/masscan file; resume is automatic by default using `targets-state.json` (or set with `--targets-state`). Disable resume with `--no-resume`.
  - `--random N`: add N random public IPv4s using the default port (22 unless overridden with `--port`).
- Credentials:
  - `--users` / `--user-file`, `--passwords` / `--pass-file`, `--combo-file`: supply creds; defaults to root/root if none given.
- Concurrency/timeouts:
  - `--max-workers`: concurrent SSH attempts; `--queue-size`: bounded work queue (set 0 for unbounded).
  - Timeouts: `--connect-timeout`, `--auth-timeout`, `--read-timeout`.
- Probing/ordering:
  - `--no-probe` to skip TCP probe, `--banner` to capture SSH banners, `--allow-non-ssh` to keep non-SSH listeners, `--no-shuffle` to disable randomization.
- Stop behavior:
  - `--stop-first-host` (stop per host on first hit), `--stop-first-global` (stop everything on first hit).
- Post-auth commands:
  - `--command` to run on success, `--no-command-output` to suppress stdout/stderr logging.
- Output/logging:
  - `--results` JSONL path (defaults to timestamped file with collision avoidance).
  - `--log-interval`, `--hang-timeout` (idle threshold before auto-stop), `--verbose` (per-attempt warnings/errors).
  - Status: single-line live status with attempts/successes, queue, rate, idle time, and optional local CPU/net usage.
  - `--no-cpu-net` to disable CPU/net sampling in status.
- Enrichment (opt-in):
  - `--gather-info` to collect system info/health on success.
  - `--post-process` (default) runs enrichment after brute in a separate pool; `--no-post-process` runs inline.
  - `--post-light` uses a smaller command set for speed; `--post-timeout` per-host info budget; `--age-cache` hostkey first-seen cache path; `--no-honeypot-detect` to disable honeypot heuristics; `--gather-concurrency` limits concurrent post tasks.
- Profiles:
  - `--profile fast|balanced|info` applies tuned defaults unless you override specific flags.

## Safety / Notes
- This code avoids storing any provided passwords locally beyond the runtime
  process. Supply credentials via CLI/files as needed.
- Designed to be an orchestrator: lean on masscan/zmap/nmap/hydra/ncrack when
  present; built-in async probing/brute is a fast fallback.
