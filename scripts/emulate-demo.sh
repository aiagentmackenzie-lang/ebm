#!/bin/bash
# Demo script for adversary emulation
set -e

EBM=${EBM:-./dist/ebm-linux-amd64}

echo "[DEMO] Running adversary emulation scenarios..."

echo "[DEMO] T1059.001 — PowerShell encoded command"
$EBM emulate --technique T1059.001 --payload "powershell -enc SGVsbG8gV29ybGQ="

echo "[DEMO] T1566.001 — Office spawning child"
$EBM emulate --technique T1566.001

echo "[DEMO] T1003.001 — LSASS access"
$EBM emulate --technique T1003.001

echo "[DEMO] T1547.001 — Registry persistence"
$EBM emulate --technique T1547.001

echo "[DEMO] T1071 — Beaconing"
$EBM emulate --technique T1071 --domain evil.com --interval 5 --jitter 1

echo "[DEMO] T1055 — Process injection"
$EBM emulate --technique T1055

echo "[DEMO] Ransomware scenario"
$EBM emulate --scenario ransomware_sim

echo "[DEMO] Done. Check SecurityScarletAI dashboard for generated alerts."
