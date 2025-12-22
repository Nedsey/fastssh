# fastssh Improvement Plan

Three-phase plan to deliver ≥20% throughput gain while improving auth accuracy. This file will be updated as work progresses.

## Phase 1 — Baseline & Design
- **Metrics to capture:** attempts/sec, successes, failures (auth vs transport vs timeout), timeouts, CPU%, RSS, queue depth, and post-processing latency (when enabled). Track per-host behaviors (throttling/lockout).
- **Safe baseline recipe (no external scans run by default):**
  - Prepare an authorized target set (host[:port]) with known-good and known-bad creds plus a few dead/slow hosts. Avoid using unsolicited IP lists.
  - Example commands (adjust paths/creds to your authorized lab):  
    - Baseline fast path: `python fastssh.py --targets lab_targets.txt --users root admin --passwords root toor --max-workers 200 --log-interval 2 --verbose --results baseline.jsonl`  
    - With post-processing: add `--gather-info --command 'uname -a' --post-light`
  - Collect runtime metrics: `time` the run; watch `top`/`pidstat` for CPU/RSS; note attempts/sec from status output and final counters; categorize failures in the JSONL.
- **Edge-case checklist:** slow banners, non-SSH listeners, SSH variants requiring keyboard-interactive, hosts with fail2ban/lockout, and honeypots. Note false negatives from timeouts vs banner reject vs auth deny.
- **Engine decision:** primary path is `ssh2-python` (libssh2) via a threadpool wrapper to reduce handshake overhead while keeping Python orchestration. External helpers (hydra/ncrack or a Go microservice) remain plan B if targets demand it.
- **Probe strategy direction:** split connect vs banner read timeouts, accept SSH signature quickly, optional cached probe results; keep banner capture when requested.
- **Acceptance targets:** +20–30% attempts/sec on the same hardware/targets, reduced timeout-derived false negatives, no regression in stop-first semantics; post-processing adds minimal overhead when enabled.

## Phase 2 — Speed/Accuracy Implementation
- Replace `asyncssh` auth path with `ssh2-python` (libssh2) wrapper that returns detailed result codes (auth failure vs transport vs kbd-int).
- Stream work generation (no full pre-enqueue), honoring stop-first-host/global to avoid wasted queue entries; add optional per-host concurrency cap.
- Reuse connections where possible (multiple auth attempts per TCP session) and reuse success session for post-success command/info to avoid a second handshake.
- Tighten probing: split connect vs banner timeouts, accept SSH signature quickly, cache probe results; keep banner capture when requested.
- Add buffered/async results writer and batch post-info commands to cut per-record I/O and round trips.

### Phase 2 progress (initial)
- Added libssh2 (`ssh2-python`) auth backend (default) with async fallback selection.
- Kept asyncssh path as fallback and for post-auth actions; optional commands/info reuse that session when available.
- Generation loop now respects stop-first-host/global mid-build to avoid queuing extra work.

## Phase 3 — Hardening & Validation
- Re-run benchmarks vs baseline; document attempts/sec, CPU, network, success/false-negative rates; verify ≥20% improvement.
- Stress-test dead/slow hosts and throttled servers to ensure hang/timeout logic works with new engine and lazy queue.
- Validate accuracy: keyboard-interactive handling, clearer error taxonomy, optional hostkey/honeypot cues; ensure stop-first semantics still honored.
- Clean up toggles and docs: new flags/defaults, migration notes, and updated README/examples reflecting performance changes.
