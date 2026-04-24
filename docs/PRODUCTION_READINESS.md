# Endpoint Behavior Monitor — Production Readiness Checklist

**Version:** 1.0  
**Date:** 2026-04-23  
**Status:** MVP Complete → Production Hardening Required

---

## Executive Summary

The EBM agent is functionally complete as an MVP: telemetry collection, rule evaluation, SQLite queuing, and SIEM ingestion all work end-to-end. However, several gaps remain before deployment to production endpoints. Use this checklist as the hardening roadmap.

---

## P0 — Blockers (Do Not Deploy Without)

| # | Gap | Risk | Fix Approach | Effort |
|---|-----|------|--------------|--------|
| P0-01 | **SQLite concurrency / locking** | Events silently dropped under load; `SQLITE_BUSY` errors observed in demo. | Open DB with `PRAGMA journal_mode=WAL`, set busy timeout (`_busy_timeout=5000`), and add `SetMaxOpenConns(1)` or a write mutex. | 2 hrs |
| P0-02 | **Platform collectors are stubs** | All platforms fallback to `gopsutil` polling. Real-time telemetry (eBPF, ETW, ESF) is not implemented. | Activate eBPF probes for Linux (`cilium/ebpf`), ETW subscriptions for Windows (`golang.org/x/sys/windows`), ESF for macOS (CGO + entitlements). Provide graceful degradation to fallback when privileged APIs are unavailable. | 2–3 days per platform |
| P0-03 | **Fallback collector memory leak** | The `seen` PID map grows forever and never prunes recycled PIDs. | Replace `map[int32]bool` with a TTL-ring or LRU cache that evicts PIDs after ~60s. | 2 hrs |
| P0-04 | **Unencrypted local storage** | `ebm_queue.db` and `agent.id` are plaintext. Bearer token is stored in `config.yaml`. | Encrypt the SQLite DB (`sqlcipher`) or encrypt event blobs with a host-derived key. Move secrets to OS keychain (macOS Keychain, Windows DPAPI, Linux `keyring`). | 1 day |
| P0-05 | **Working-directory fragility** | DB and agent ID use relative paths (`./ebm_queue.db`, `./agent.id`). Systemd/launchd may set CWD to `/`. | Resolve all runtime paths against a fixed state directory: `/var/lib/ebm/` on Linux, `%ProgramData%\EBM` on Windows, `/Library/Application Support/EBM` on macOS. | 4 hrs |

---

## P1 — High Priority (Deployable with monitoring)

| # | Gap | Risk | Fix Approach | Effort |
|---|-----|------|--------------|--------|
| P1-01 | **Rule engine cannot evaluate CIDR / "NOT" logic** | The `beaconing.yaml` rule uses `destination.ip: "NOT 10.0.0.0/8"`, which the engine treats as a literal string. Rule is dead code. | Implement subnet parsing (`net.ParseCIDR`) and add a `|cidr`/`|not_cidr` modifier. Alternatively, rewrite rules to use the already-supported `not_in` modifier with a `[string]` list. | 4 hrs |
| P1-02 | **No stateful / correlation detection** | Rules like beaconing require time-window aggregation (e.g., 5 identical outbound connections). Engine evaluates events atomically. | Add a correlation module with sliding-window aggregators keyed by `(host, process, destination)`. Evaluate after flush or on tick. | 1 day |
| P1-03 | **Rule engine does not hot-reload** | `reload_interval_sec: 60` is present in config but ignored. New rules require agent restart. | Add a file watcher (`fsnotify`) or polling reloader that calls `engine.New()` and atomically swaps the rule set. | 4 hrs |
| P1-04 | **Network event deduplication missing** | Fallback collector emits every active connection every 5s, generating massive duplicates. | Cache open 4-tuples and only emit on state changes (new connection, close). | 4 hrs |
| P1-05 | **No circuit breaker / backpressure** | If SIEM is down, the agent endlessly retries and the queue grows unbounded. `max_size_mb` is not enforced. | Implement disk quota checks on insert; switch `transportWorker` to exponential backoff with a circuit breaker. Enforce `max_size_mb` with `PRAGMA page_count`. | 6 hrs |
| P1-06 | **Alert deduplication / throttling** | The same rule firing on every process snapshot will flood alerts. | Add a per-rule throttle (e.g., one alert per host per 15 minutes) using an in-memory TTL map or SQLite dedup table. | 4 hrs |

---

## P2 — Medium Priority (Operational polish)

| # | Gap | Risk | Fix Approach | Effort |
|---|-----|------|--------------|--------|
| P2-01 | **WebSocket config is dead code** | `ws_url` is parsed from config but never used. | Implement `transport/ws.go` that dials the WebSocket and streams events in real-time alongside the HTTP batch path. | 1 day |
| P2-02 | **Missing metrics / observability** | No Prometheus / pprof / structured log counters. Hard to debug why an alert did/didn’t fire. | Add `internal/metrics/` with counters for `events_ingested`, `alerts_triggered`, `events_sent`, `events_dropped`, `sqlite_queue_depth`. Expose a `/metrics` HTTP endpoint. | 6 hrs |
| P2-03 | **No runtime config updates** | Changing log level, batch size, or rules dir requires restart. | Watch `config.yaml` with `fsnotify` and atomically reload safe fields (batch size, log level, rules dir). | 4 hrs |
| P2-04 | **Cross-compilation warnings** | The `Makefile` sets `CGO_ENABLED=0`, which prevents eBPF/ESF builds when ready. | Split Makefile into `build-darwin`/`build-linux`/`build-windows` with conditional CGO. Provide `make build-cgo` for platforms that support it. | 2 hrs |
| P2-05 | **Empty documentation** | `docs/` is scaffolded but empty. | Write `docs/ARCHITECTURE.md` (pipeline diagram), `docs/SCHEMA.md` (event field reference), `docs/MITRE_MAPPING.md` (rule coverage). | 4 hrs |
| P2-06 | **No code-signing / notarization plan** | macOS ESF and Windows ETW both require signed binaries. | Document the code-signing cert flow (Apple Developer ID / Microsoft EV cert). Add `codesign` and `notarytool` steps to CI/CD. | 2 days (external dependency) |

---

## P3 — Nice to Have (Future enhancements)

| # | Gap | Fix Approach |
|---|-----|--------------|
| P3-01 | **Single-binary distribution** | Use `embed` to bundle eBPF object files and rule YAMLs into the Go binary so the agent ships as one static file. |
| P3-02 | **Automated eBPF probe generation** | Add `go generate` step that compiles `ebpf/probes/*.bpf.c` into `*_bpfel.o` via `cilium/ebpf` tools. |
| P3-03 | **Response actions** | Implement `internal/responder/` for process isolation, network block, or file quarantine (requires elevated privileges). |
| P3-04 | **Threat intel enrichment** | Enrich `destination.ip` and `file.hash` against MISP / VirusTotal before queuing. |

---

## Acceptance Criteria for "Production Ready"

- [ ] `make test` passes on Linux, macOS, and Windows runners (CI).
- [ ] Agent runs for 7 days on a live endpoint without `SQLITE_BUSY`, memory growth, or goroutine leaks.
- [ ] `ebm emulate --technique T1566.001` triggers the office-spawning rule and the alert appears in the SIEM within 15 seconds.
- [ ] Agent buffers 10,000+ events offline and drains the queue successfully when the SIEM returns.
- [ ] Bearer token is not present in plaintext on disk (keychain / DPAPI / keyring).
- [ ] `ebm -list-rules` reflects rule changes within 60 seconds of file modification.

---

*Prepared by Agent Mackenzie — 2026-04-23*
