# EBM — Endpoint Behavior Monitor

> Lightweight, cross-platform endpoint telemetry agent with built-in detection rules and adversary emulation.

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-v1.0-orange?style=flat)

EBM is a single-binary endpoint agent that collects process, network, file, DNS, and registry telemetry — normalizes it into an ECS-style schema — evaluates behavioral detection rules on-device — and streams everything to your SIEM with offline resilience. It also includes a built-in adversary emulation module for purple-team validation.

**Built to pair with [SecurityScarletAI](https://github.com/aiagentmackenzie-lang/securityscarletai)**, but works with any HTTP-ingesting SIEM.

---

## Why This Exists

SOC analysts need to understand endpoint telemetry from collection to detection. Most EDR tools are black boxes. EBM demonstrates end-to-end:

- **Cross-platform collection** — eBPF (Linux), Endpoint Security Framework (macOS), ETW/Sysmon (Windows)
- **Data normalization** — Raw OS events → ECS-style schema → flattened SIEM format
- **On-agent detection** — YAML rules evaluated locally before events leave the endpoint
- **Offline resilience** — SQLite queue with exponential backoff, events never lost
- **Adversary emulation** — Generate ground-truth malicious behavior, validate your detections live

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        EBM Agent                            │
│                                                             │
│  OS Telemetry APIs                                          │
│  (eBPF / ESF / Sysmon)                                     │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────┐   ┌───────────┐   ┌──────────┐              │
│  │ Collector │→ │ Normalizer │→ │  Rule     │              │
│  │ (per-OS)  │   │ (ECS/OCSF)│   │  Engine  │              │
│  └──────────┘   └─────┬─────┘   └────┬─────┘              │
│                       │              │                       │
│                       ▼              ▼                       │
│              ┌─────────────────────────────┐                │
│              │     SQLite Event Queue       │                │
│              │  (pending → sent / failed)   │                │
│              └──────────────┬──────────────┘                │
│                             │                                │
│                             ▼                                │
│              ┌─────────────────────────────┐                │
│              │   HTTP Batcher + Backoff     │                │
│              │   POST /api/v1/ingest        │────→ SIEM     │
│              └─────────────────────────────┘                │
│                                                             │
│  ┌──────────────┐                                          │
│  │  Emulator     │  (optional, purple-team CLI)             │
│  └──────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Build for all platforms
make build

# Configure
cp config.yaml.example config.yaml
export SCARLET_TOKEN="your-siem-token"

# Run the agent
./dist/ebm-darwin-arm64 -config config.yaml

# List loaded detection rules
./dist/ebm-darwin-arm64 -config config.yaml -list-rules

# Run adversary emulation
./dist/ebm-darwin-arm64 -config config.yaml -emulate -technique T1566.001
./dist/ebm-darwin-arm64 -config config.yaml -emulate -scenario ransomware_sim
```

### Integration Test

```bash
./scripts/integration_test.sh
```

Starts a mock HTTP server, runs the agent, triggers emulation, and verifies the SIEM receives events.

---

## Detection Rules

Rules are YAML files in `rules/`. Each rule maps MITRE techniques to behavioral conditions:

```yaml
id: ebm-rule-001
name: "Office Spawning Suspicious Child Process"
description: Detects Office applications launching interpreters or suspicious binaries
mitre:
  technique: "T1566.001"
  tactic: "Initial Access"
severity: high
condition:
  event.type: "process_start"
  process.parent.name: ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
  process.name: ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "mshta.exe"]
```

### Built-in Rules

| Rule | MITRE | What It Detects |
|------|-------|-----------------|
| Office Spawning | T1566.001 | Word/Excel/PowerPoint spawning cmd/powershell |
| LSASS Access | T1003.001 | Suspicious process access to LSASS (credential dumping) |
| Network Beaconing | T1071 | Low-jitter outbound connections from unusual processes |
| Registry Persistence | T1547.001 | Modifications to Run/RunOnce registry keys |

### Rule Condition Syntax

| Syntax | Meaning |
|--------|---------|
| `field: "value"` | Exact case-insensitive match |
| `field: ["a", "b"]` | Match any value in list (OR) |
| `field\|contains: "str"` | Substring match |
| `field\|startswith: "str"` | Prefix match |
| `field\|endswith: "str"` | Suffix match |
| `field: "NOT x"` | Negation (custom logic) |

Rules hot-reload every 60 seconds (configurable).

---

## Adversary Emulation

Generate ground-truth malicious events to validate your detection pipeline end-to-end:

```bash
# Individual techniques
./ebm -config config.yaml -emulate -technique T1059.001   # PowerShell encoded command
./ebm -config config.yaml -emulate -technique T1566.001   # Office → suspicious child
./ebm -config config.yaml -emulate -technique T1003.001   # LSASS credential dumping
./ebm -config config.yaml -emulate -technique T1547.001   # Registry Run key persistence
./ebm -config config.yaml -emulate -technique T1071       # Network beaconing
./ebm -config config.yaml -emulate -technique T1055       # Process injection

# Multi-step scenario
./ebm -config config.yaml -emulate -scenario ransomware_sim
```

Emulation events are tagged `event.type: emulation` so they appear in the SIEM alongside real detections, clearly labeled.

---

## Event Schema

### Internal EDR Core Schema (ECS-style)

| Field | Description |
|-------|-------------|
| `@timestamp` | ISO 8601 event time |
| `event.type` | `process_start`, `network_connect`, `file_create`, `registry_set`, etc. |
| `process.name` | Process binary name |
| `process.command_line` | Full command line |
| `process.parent.name` | Parent process |
| `source.ip` / `destination.ip` | Network endpoints |
| `user.name` | Executing user |
| `mitre.technique_id` | ATT&CK technique(s) |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |

### Flattened SecurityScarletAI Format

Events are flattened into the SIEM's ingest schema before sending:

```json
{
  "@timestamp": "2026-04-23T14:30:00Z",
  "host_name": "devbox-01",
  "source": "endpoint_behavior_monitor",
  "event_category": "process",
  "event_type": "start",
  "user_name": "raphael",
  "process_name": "powershell.exe",
  "severity": "high"
}
```

---

## Offline Resilience

EBM never loses events. The SQLite queue ensures delivery even when the SIEM is unreachable:

1. **Normalize** → Write to `event_queue` as `pending`
2. **Batch** → Select up to 50 pending events (configurable)
3. **Health Check** → `GET /api/v1/health` before flushing
4. **Send** → `POST /api/v1/ingest` with Bearer auth
5. **On 202** → Delete from queue (delivered)
6. **On failure** → Increment `retry_count`, apply exponential backoff with jitter (`min(300s, 2^n * 1s + rand)`)
7. **After 5 retries** → Mark `failed`, stop retrying

---

## Configuration

See [`config.yaml.example`](config.yaml.example) for the full reference.

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `agent` | `id` | auto-generated | UUID; persisted to `agent.id` |
| `siem` | `url` | `http://localhost:8000/api/v1/ingest` | SIEM ingest endpoint |
| `siem` | `bearer_token` | `${SCARLET_TOKEN}` | Auth token (env var or literal) |
| `siem` | `batch_size` | 50 | Max events per batch |
| `siem` | `flush_interval_sec` | 10 | Seconds between flushes |
| `collection` | `process_events` | true | Collect process starts/stops |
| `collection` | `network_events` | true | Collect network connections |
| `rules` | `rules_dir` | `./rules` | Path to YAML detection rules |
| `rules` | `reload_interval_sec` | 60 | Hot-reload interval |
| `storage` | `db_path` | `./ebm_queue.db` | SQLite queue path |
| `storage` | `retention_hours` | 72 | Auto-cleanup age |

---

## Platform Collection

| Telemetry | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| **Process Start/Stop** | Sysmon EID 1/5, ETW | eBPF `execve` tracepoint | ESF `AUTH_EXEC` / `NOTIFY_EXIT` |
| **Network Connection** | Sysmon EID 3, ETW TcpIp | eBPF `tcp_connect` | ESF `NOTIFY_CONNECT` |
| **DNS Query** | Sysmon EID 22 | eBPF `getaddrinfo` | dnssd / BSM fallback |
| **File Create/Modify/Delete** | Sysmon EID 11/23/26 | eBPF `security_file_open` | ESF `NOTIFY_CREATE/RENAME/UNLINK` |
| **Registry / Plist** | Sysmon EID 12/13/14 | eBPF on crontab/systemd | ESF on LaunchAgents/LaunchDaemons |
| **Image/DLL Load** | Sysmon EID 7 | eBPF `mmap PROT_EXEC` | ESF `NOTIFY_MMAP` |
| **Cross-Process Access** | Sysmon EID 8/10 | eBPF `ptrace` | ESF `task_for_pid` / FSEvents fallback |

macOS degrades gracefully from ESF to FSEvents+OpenBSM when unsigned. Linux falls back from eBPF to auditd+/proc when unprivileged.

---

## Build

```bash
make build           # All platforms (Linux, Windows, macOS ARM64)
make build-linux      # Linux amd64
make build-darwin     # macOS ARM64
make build-windows    # Windows amd64
make test             # Run tests
make clean            # Remove dist/
```

Single static binary per platform. No CGO, no runtime dependencies.

---

## Project Structure

```
cmd/ebm/main.go           # CLI entry point
internal/
  agent/agent.go          # Agent lifecycle (start/stop/health)
  collector/              # Platform telemetry collectors
    collector.go           # Interface + fallback (gopsutil)
    linux.go               # eBPF probes (future)
    fallback.go            # gopsutil-based collection
  config/config.go         # YAML config loader
  engine/                  # Detection rule engine
    engine.go              # Rule matching with modifiers
    engine_test.go         # Unit tests
  emulator/emulator.go    # Adversary emulation (6 techniques + scenarios)
  model/event.go          # Event, IngestEvent, Alert data models
  normalizer/             # Event normalization
    normalizer.go          # Platform → EDR Core Schema
    ecs_mapper.go          # ECS field mapping
    pipeline.go            # Normalize → enrich → flatten pipeline
    scarlet_flatten.go     # EDR Core → SecurityScarletAI IngestEvent
  storage/
    sqlite.go              # Persistent event queue
    retention.go           # Auto-cleanup by age
  transport/
    client.go              # HTTP batching + Bearer auth
    backoff.go             # Exponential backoff with jitter
rules/                     # YAML detection rules
scripts/                  # Install, integration test, demo
```

---

## Integration with SecurityScarletAI

EBM sends events to SecurityScarletAI's ingest API:

| Contract | Value |
|----------|-------|
| **Endpoint** | `POST /api/v1/ingest` |
| **Auth** | `Authorization: Bearer <SCARLET_TOKEN>` |
| **Content-Type** | `application/json` |
| **Success** | `202 Accepted` |
| **Batch Limit** | 50 events per request |
| **WebSocket** | `ws://host:8000/api/v1/ws/logs?token=<TOKEN>` |
| **Source Tag** | `endpoint_behavior_monitor` |

Works with any HTTP-ingesting SIEM — just point `siem.url` at your endpoint.

---

## License

MIT

---

*Part of the [GHOSTWIRE](https://github.com/aiagentmackenzie-lang/GHOSTWIRE) → EBM → [SecurityScarletAI](https://github.com/aiagentmackenzie-lang/securityscarletai) detection pipeline.*