# Endpoint Behavior Monitor

**Endpoint Behavior Monitor (EBM)** is a lightweight, cross-platform endpoint telemetry collection and behavioral detection agent built in Go. It normalizes events into an ECS-inspired schema and streams them to **SecurityScarletAI** for correlation and alerting. It includes a built-in adversary emulation CLI for purple-team validation.

## Quick Start

```bash
# Build for all platforms
make build

# Configure
export SCARLET_TOKEN="your-siem-token"
cp config.yaml.example config.yaml

# Run the agent
./dist/ebm-darwin-arm64 -config config.yaml

# Run emulation demo
./scripts/emulate-demo.sh
```

## Architecture

- **Collectors** — Platform-specific telemetry ingestion (eBPF on Linux, ETW/Sysmon on Windows, ESF on macOS)
- **Normalizer** — Maps raw platform events to a cross-platform EDR Core Schema
- **Rule Engine** — Lightweight YAML-based detection engine running on the endpoint
- **SQLite Queue** — Offline-resilient event persistence with retry logic
- **Transport** — HTTPS batching to SecurityScarletAI with backoff

## Detection Rules

Detection rules live in `rules/` as YAML files. See `rules/office_spawning.yaml` for an example.

## Adversary Emulation

```bash
# Emulate PowerShell encoded command (T1059.001)
./ebm emulate --technique T1059.001

# Emulate LSASS access (T1003.001)
./ebm emulate --technique T1003.001

# Full scenario
./ebm emulate --scenario ransomware_sim
```

## License

MIT
