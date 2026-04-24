# Endpoint Behavior Monitor
## Project Specification & Architecture Document
**Version:** 1.0  
**Date:** 2026-04-23  
**Status:** Final — Build Approved  

---

## 1. Executive Summary & Interview Narrative

**Endpoint Behavior Monitor** is a lightweight, cross-platform endpoint telemetry collection and behavioral detection agent. It captures real-time endpoint activity (processes, network, file system, registry, and more), normalizes events into an industry-standard schema, and streams them into **SecurityScarletAI** for correlation, alerting, and incident triage.

**Why it matters:** SOC analysts spend 70% of their time in EDR consoles. This project demonstrates deep understanding of:
- Cross-platform endpoint telemetry APIs (eBPF, ETW, Endpoint Security Framework)
- Data normalization (ECS/OCSF-inspired schema design)
- Detection engineering (Sigma-like rule execution on the endpoint)
- Adversary emulation integration (purple-team validation)
- Resilient agent architecture (offline queuing, batching, health checks)

**Interview story:**
> *"I built an endpoint behavior monitor that uses eBPF on Linux, Apple's Endpoint Security Framework on macOS, and integrates with Sysmon on Windows to collect process, network, and file telemetry. Events are normalized into an ECS-style schema and streamed into my SIEM. It includes a built-in adversary emulation module so I can simulate LSASS credential dumping or beaconing behavior and watch my own EDR detect it in real-time. I understand both the telemetry pipeline and the detection engineering behind it."*

---

## 2. Goals & Non-Goals

### Goals
| # | Goal |
|---|------|
| G1 | Collect real-time endpoint telemetry on **Windows, macOS, and Linux** |
| G2 | Normalize all events into a **cross-platform "EDR Core Schema"** compatible with SecurityScarletAI |
| G3 | Implement an **on-agent detection rule engine** for behavioral analytics |
| G4 | Provide **offline resilience** (local SQLite queue with retry logic) |
| G5 | Include a **built-in adversary emulation CLI** for purple-team validation |
| G6 | Deploy as a **single static binary** per platform |

### Non-Goals
| # | Non-Goal | Rationale |
|---|----------|-----------|
| NG1 | Kernel driver development | Use user-space APIs only (eBPF, ETW, ESF). Kernel drivers require EV signing. |
| NG2 | Response / remediation actions | This is a detection and telemetry tool. Active response is a future phase. |
| NG3 | Full Sigma rule parser | Implement a simplified JSON rule format sufficient for ~10 core detections. |
| NG4 | Production-grade key management | Agent auth tokens live in a local config file. Rotation is a stretch goal. |
| NG5 | GUI dashboard | SecurityScarletAI serves as the backend/dashboard. The agent is CLI-only. |

---

## 3. System Architecture

```
Endpoint OS APIs → Normalizer → Rule Engine → SQLite Queue → HTTP Batcher → SecurityScarletAI
```

### Detailed Flow
1. **Collector (per platform)** ingests raw OS telemetry.
2. **Normalizer** maps platform-specific fields to the **EDR Core Schema**.
3. **Rule Engine** evaluates normalized events against behavioral rules.
4. **SQLite Queue** persists events with `pending`/`sent`/`failed` status for offline resilience.
5. **HTTP Batcher** flushes batches (max 50 events / 10s) to SecurityScarletAI.
6. **Backoff** applies exponential backoff with jitter on transport failure.

---

## 4. Platform Collection Matrix

| Telemetry Primitive | Windows | Linux | macOS |
|---|---|---|---|
| **Process Start/Stop** | Sysmon EID 1/5, ETW `Kernel-Process` | eBPF `tracepoint/syscalls/sys_enter_execve`, `sched/sched_process_exit` | ESF `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_NOTIFY_EXIT` |
| **Network Connection** | Sysmon EID 3, ETW `TcpIp` | eBPF `kprobe/tcp_connect`, `kprobe/inet_csk_accept` | ESF `ES_EVENT_TYPE_NOTIFY_CONNECT` (or `NEFilterDataProvider` fallback) |
| **DNS Query** | Sysmon EID 22, ETW `DNS-Client` | eBPF `tracepoint/syscalls/sys_enter_getaddrinfo` | `dnssd` / BSM audit fallback |
| **File Create/Modify/Delete** | Sysmon EID 11/23/26, ETW `Kernel-File` | eBPF `security_file_open`, `vfs_unlink`, `fanotify` | ESF `ES_EVENT_TYPE_NOTIFY_CREATE/RENAME/UNLINK`, FSEvents fallback |
| **Image/DLL Load** | Sysmon EID 7 | eBPF `mmap` with `PROT_EXEC` | ESF `ES_EVENT_TYPE_NOTIFY_MMAP` |
| **Registry / Plist** | Sysmon EID 12/13/14 | eBPF on `/etc/crontab`, `/etc/systemd/system/`, `~/.bashrc` | ESF file events on `~/Library/LaunchAgents`, `/Library/LaunchDaemons` |
| **Cross-Process Access** | Sysmon EID 8/10 | eBPF `__x64_sys_ptrace` | ESF `task_for_pid` audit / signals |
| **Driver / Kext Load** | Sysmon EID 6 | eBPF `do_init_module` | ESF `ES_EVENT_TYPE_AUTH_KEXTLOAD` |
| **Named Pipes** | Sysmon EID 17/18 | eBPF tracepoint on FIFO `write` | ESF / `kqueue` on pipe files |
| **Persistence (Tasks)** | Sysmon/WMI EID 19/20/21, Event IDs 4698 | eBPF on `/var/spool/cron/`, `auditd -w` | ESF on plist paths, `launchd` |
| **User / Session** | Event ID 4624/4625, Sysmon user info | `auditd` login events | OpenBSM `user_login` events |

---

## 5. Data Model & Schema

### 5.1 Internal EDR Core Schema (ECS-Like)

```json
{
  "@timestamp": "2026-04-23T14:30:00.000Z",
  "event.type": "process_start",
  "event.platform": "linux",
  "event.provider": "ebpf",
  "host.hostname": "devbox-01",
  "host.os.type": "linux",
  "host.os.version": "Ubuntu 24.04",
  "host.ip": ["10.0.0.15"],
  "agent.id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "agent.version": "1.0.0",
  "user.name": "raphael",
  "user.id": "1000",
  "process.pid": 12345,
  "process.name": "python3",
  "process.command_line": "python3 -c 'import socket; socket.connect(...)'",
  "process.executable": "/usr/bin/python3",
  "process.hash.sha256": "abc123...",
  "process.parent.pid": 1000,
  "process.parent.name": "bash",
  "process.parent.command_line": "bash",
  "network.direction": "outbound",
  "network.transport": "tcp",
  "source.ip": "10.0.0.15",
  "source.port": 54321,
  "destination.ip": "185.220.101.47",
  "destination.port": 443,
  "destination.domain": "evil.com",
  "file.path": null,
  "registry.path": null,
  "mitre.technique_id": ["T1071"],
  "mitre.tactic": ["Command and Control"],
  "severity": "info"
}
```

### 5.2 Flattened SecurityScarletAI IngestEvent

The agent flattens the EDR Core Schema into the exact schema expected by the SIEM:

```json
{
  "@timestamp": "2026-04-23T14:30:00.000Z",
  "host_name": "devbox-01",
  "source": "endpoint_behavior_monitor",
  "event_category": "process",
  "event_type": "start",
  "event_action": "process_started",
  "raw_data": { },
  "user_name": "raphael",
  "process_name": "python3",
  "process_pid": 12345,
  "source_ip": "10.0.0.15",
  "destination_ip": "185.220.101.47",
  "destination_port": 443,
  "file_path": null,
  "file_hash": "abc123...",
  "severity": "info"
}
```

---

## 6. MITRE ATT&CK Telemetry Mapping

| Data Source | Techniques Detected | Required Events |
|---|---|---|
| **Process Creation** | T1059, T1204, T1566 | `process_start` with parent/child |
| **Process Access / Remote Thread** | T1055, T1003.001, T1134 | `process_access`, `create_remote_thread` |
| **Network Connection** | T1071, T1021, T1041, T1048 | `network_connect` with process attribution |
| **DNS Query** | T1071.004 | `dns_query` |
| **File System** | T1204, T1547.001, T1486, T1070.004 | `file_create`, `file_modify`, `file_delete` |
| **Registry / Plist** | T1547.001, T1112, T1546 | `registry_set`, `registry_create` |
| **Image Load** | T1574, T1055, T1218 | `image_load` |
| **Scheduled Task / Cron** | T1053 | `job_created` |
| **WMI Event** | T1047 | `wmi_event_created` |

### Detection Rule Examples

#### Office Spawning Suspicious Child (T1566 → T1059)
```yaml
condition:
  event.type: process_start
  process.parent.name: [winword.exe, excel.exe, powerpnt.exe, outlook.exe]
  process.name: [cmd.exe, powershell.exe, pwsh.exe, wscript.exe, cscript.exe, mshta.exe, regsvr32.exe, rundll32.exe]
```

#### LSASS Credential Dumping (T1003.001)
```yaml
condition:
  event.type: process_access
  target.process.name: lsass.exe
  granted_access: [0x1010, 0x1F0FFF, 0x1410, 0x143A]
  source.process.name: NOT [svchost.exe, services.exe, smss.exe, csrss.exe]
```

#### PowerShell Encoded Command (T1059.001)
```yaml
condition:
  event.type: process_start
  process.name: [powershell.exe, pwsh.exe]
  process.command_line: contains_any [-enc, -encodedcommand, -ec]
```

#### Registry Run Key Persistence (T1547.001)
```yaml
condition:
  event.type: [registry_set, registry_create]
  registry.path: contains \CurrentVersion\Run
  process.name: NOT [trusted_installer.exe, msiexec.exe]
```

---

## 7. Configuration & Policy Management

### 7.1 Agent Config (`config.yaml`)

```yaml
agent:
  id: ""                      # Auto-generated UUID on first run if empty
  version: "1.0.0"
  log_level: info

siem:
  url: "http://localhost:8000/api/v1/ingest"
  ws_url: "ws://localhost:8000/api/v1/ws/logs"
  bearer_token: "${SCARLET_TOKEN}"  # Or env var override
  batch_size: 50
  flush_interval_sec: 10
  health_check_url: "http://localhost:8000/api/v1/health"
  health_check_interval_sec: 30
  timeout_sec: 10

collection:
  enabled: true
  process_events: true
  network_events: true
  file_events: true
  dns_events: true
  registry_events: true
  image_load_events: true

rules:
  enabled: true
  rules_dir: "./rules"
  reload_interval_sec: 60

storage:
  db_path: "./ebm_queue.db"
  max_size_mb: 100
  retention_hours: 72

emulator:
  enabled: true               # Can be disabled in production mode
```

---

## 8. Offline Resilience & Transport Logic

### 8.1 SQLite Queue Schema

```sql
CREATE TABLE IF NOT EXISTS event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending','sent','failed')) DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at TIMESTAMP
);

CREATE INDEX idx_status ON event_queue(status);
CREATE INDEX idx_created ON event_queue(created_at);
```

### 8.2 Transport Flow
1. **Normalize** → Write to `event_queue` as `pending`.
2. **Batch** → Select up to `batch_size` pending events ordered by `created_at`.
3. **Health Check** → `GET /api/v1/health` before flushing. If unhealthy, defer.
4. **Send** → `POST /api/v1/ingest` with `Authorization: Bearer <token>`.
5. **On 202** → Mark batch as `sent`, delete from queue.
6. **On failure** → Increment `retry_count`, re-mark `pending` (or `failed` after 5 retries). Apply **exponential backoff with jitter**:
   `backoff = min(300s, 2^retry_count * 1s + random(0,1s))`.

---

## 9. Integration Contract (SecurityScarletAI)

| Contract Element | Value |
|---|---|
| **Protocol** | HTTP/1.1 |
| **Auth** | `Authorization: Bearer <SCARLET_TOKEN>` |
| **Ingest Endpoint** | `POST /api/v1/ingest` |
| **Batch Limit** | Max 1,000 events per request |
| **Success Code** | `202 Accepted` |
| **Response Body** | `{ "accepted": N, "message": "Accepted N events" }` |
| **WebSocket** | `ws://host:8000/api/v1/ws/logs?token=<TOKEN>` |
| **Agent Source Tag** | `endpoint_behavior_monitor` |
| **Required Fields** | `@timestamp`, `host_name`, `source`, `event_category`, `event_type` |
| **Asset Correlation** | `host_name` must be stable per endpoint (persist `agent.id` → map to `host_name`) |

---

## 10. Adversary Emulation Module

A built-in CLI command to generate ground-truth malicious behavior for purple-team validation:

```bash
# Simulate process injection chain
./ebm emulate --technique T1059.001 --payload "powershell -enc SGVsbG8gV29ybGQ="

# Simulate credential dumping access
./ebm emulate --technique T1003.001 --target lsass.exe

# Simulate beaconing C2
./ebm emulate --technique T1071 --domain evil.com --interval 30s --jitter 5s

# Simulate ransomware file behavior
./ebm emulate --scenario ransomware_sim --target-dir /tmp/test_data
```

### Supported Techniques (Phase 1)
| Technique | Emulated Behavior |
|---|---|
| **T1059.001** | Spawn PowerShell with encoded command |
| **T1566.001** | Simulate Office → cmd/powershell parent-child |
| **T1003.001** | Access LSASS (simulated handle open on non-Windows) |
| **T1547.001** | Write to Run key / LaunchAgent plist |
| **T1071** | Beaconing connection to test domain at regular intervals |
| **T1055** | Simulate process injection via `ptrace` (Linux) or remote thread (Windows) |

Emulation events are injected into the same pipeline with `event.type: emulation` so they appear in the SIEM dashboard alongside real detections.

---

## 11. Build Plan & Directory Layout

### 11.1 Tech Stack

| Component | Choice |
|---|---|
| **Language** | Go 1.22+ |
| **eBPF (Linux)** | `cilium/ebpf` |
| **Windows ETW / Sysmon** | `golang.org/x/sys/windows` |
| **macOS ESF** | CGO bindings to `EndpointSecurity` framework |
| **SQLite** | `modernc.org/sqlite` (pure Go, no CGO) |
| **Config** | `gopkg.in/yaml.v3` |
| **HTTP Client** | `net/http` (stdlib) |
| **Rule Engine** | Custom rule matcher (`map[string]Rule`) |
| **Logging** | `log/slog` (stdlib) |

### 11.2 Directory Structure

```
Endpoint_Behavior_Monitor/
├── SPEC.md
├── README.md
├── Makefile
├── go.mod
├── cmd/
│   └── ebm/
│       └── main.go
├── internal/
│   ├── agent/
│   │   ├── agent.go
│   │   ├── config.go
│   │   └── version.go
│   ├── collector/
│   │   ├── collector.go
│   │   ├── windows.go
│   │   ├── linux.go
│   │   ├── darwin.go
│   │   └── fallback.go
│   ├── normalizer/
│   │   ├── normalizer.go
│   │   ├── ecs_mapper.go
│   │   └── scarlet_flatten.go
│   ├── engine/
│   │   ├── engine.go
│   │   ├── loader.go
│   │   └── compiler.go
│   ├── storage/
│   │   ├── sqlite.go
│   │   └── retention.go
│   ├── transport/
│   │   ├── client.go
│   │   ├── batcher.go
│   │   └── backoff.go
│   ├── emulator/
│   │   ├── emulator.go
│   │   ├── techniques.go
│   │   └── scenarios.go
│   └── model/
│       └── event.go
├── ebpf/
│   ├── probes/
│   │   ├── execve.bpf.c
│   │   ├── tcp_connect.bpf.c
│   │   └── file_open.bpf.c
│   └── gen.go
├── rules/
│   ├── office_spawning.yaml
│   ├── lsass_access.yaml
│   ├── beaconing.yaml
│   └── registry_persistence.yaml
├── scripts/
│   ├── install.sh
│   ├── install.ps1
│   └── emulate-demo.sh
└── docs/
    ├── ARCHITECTURE.md
    ├── SCHEMA.md
    └── MITRE_MAPPING.md
```

### 11.3 Build Targets

```makefile
build-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/ebm-linux-amd64 ./cmd/ebm

build-windows:
	GOOS=windows GOARCH=amd64 go build -o dist/ebm-windows-amd64.exe ./cmd/ebm

build-darwin:
	GOOS=darwin GOARCH=arm64 go build -o dist/ebm-darwin-arm64 ./cmd/ebm

build-all: build-linux build-windows build-darwin
```

---

## 12. Demo Scenarios & Success Criteria

### Scenario A: Detect Office → PowerShell (T1566.001)
1. **Emulate:** `ebm emulate --technique T1566.001`
2. **Collect:** Agent ingests process start event.
3. **Detect:** Rule engine matches `parent.name IN [winword.exe, ...]` AND `process.name == powershell.exe`.
4. **Alert:** Severity `high` alert sent to SecurityScarletAI.
5. **Verify:** Dashboard shows alert with full process tree.

### Scenario B: Credential Dumping (T1003.001)
1. **Emulate:** `ebm emulate --technique T1003.001`
2. **Collect:** Windows: Sysmon EID 10 (ProcessAccess) to LSASS.
3. **Detect:** Rule matches `target.process.name == lsass.exe` AND `granted_access` bitmask suspicious.
4. **Alert:** Critical alert in SIEM.

### Scenario C: Beaconing (T1071)
1. **Emulate:** `ebm emulate --technique T1071 --interval 30s`
2. **Collect:** Agent streams network connections.
3. **Detect:** Batcher aggregates connections over 5-minute window; low jitter, identical destination.
4. **Alert:** Medium alert for suspicious beaconing pattern.

### Success Criteria
| ID | Criteria | Validation |
|---|---|---|
| SC1 | Agent runs on all 3 platforms without kernel modifications | Build + run tests on Win/Mac/Linux VMs |
| SC2 | Telemetry appears in SecurityScarletAI within 15 seconds of event | Stopwatch test with `ping` or `ls` |
| SC3 | Agent buffers 10,000+ events offline and drains when SIEM returns | Disconnect network, generate events, reconnect, verify ingestion |
| SC4 | At least 5 MITRE techniques can be emulated and detected | Run each emulation CLI command; verify alert |
| SC5 | Single static binary per platform | `ldd` check (none), file size < 25MB |

---

## 13. Open Questions / Stretch Goals

1. **Windows Sysmon dependency:** Bundle a minimal `sysmon_config.xml` and a setup script, or assume user installs Sysmon separately. *(Decision: Bundle minimal config and setup script.)*
2. **macOS entitlements:** ESF requires `com.apple.developer.endpoint-security.client`. Document code-signing requirement; default to FSEvents + OpenBSM fallback for unsigned testing.
3. **Privilege requirements:** Linux eBPF needs `CAP_BPF` or root. Gracefully degrade to `auditd` + `/proc` parsing when unprivileged, logging a warning.

---

*Prepared by Agent Mackenzie — 2026-04-23*
