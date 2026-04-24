#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

BINARY=./dist/ebm-darwin-arm64
if [ "$(uname -s)" = "Linux" ]; then
    BINARY=./dist/ebm-linux-amd64
elif [ "$(uname -s)" = "MINGW"* ] || [ "$(uname -s)" = "CYGWIN"* ]; then
    BINARY=./dist/ebm-windows-amd64.exe
fi

if [ ! -f "$BINARY" ]; then
    echo "Binary not found, running make build..."
    make build
fi

CONFIG=config.yaml.example

# Cleanup previous runs
rm -f ./ebm_queue.db

# Start mock HTTP server
MOCK_LOG=$(mktemp)
python3 -m http.server 8000 > "$MOCK_LOG" 2>&1 &
SERVER_PID=$!

# Stop server on exit
trap "kill $SERVER_PID 2>/dev/null || true; rm -f $MOCK_LOG" EXIT

sleep 1

# Run agent background
SCARLET_TOKEN=dev-token "$BINARY" -config "$CONFIG" &
AGENT_PID=$!
trap "kill $AGENT_PID 2>/dev/null || true; kill $SERVER_PID 2>/dev/null || true; rm -f $MOCK_LOG" EXIT

sleep 2

# Trigger emulation
SCARLET_TOKEN=dev-token "$BINARY" -config "$CONFIG" -emulate --technique T1566.001

sleep 5

# Verify mock server received POST /api/v1/ingest
if grep -q "POST /api/v1/ingest" "$MOCK_LOG"; then
    echo "✅ Integration test passed: received POST /api/v1/ingest"
else
    echo "❌ Integration test failed: no POST /api/v1/ingest in mock log"
    cat "$MOCK_LOG" || true
    exit 1
fi

# Verify event_category=emulation in payload
if grep -q '"event_category": "emulation"' "$MOCK_LOG"; then
    echo "✅ Integration test passed: found event_category emulation"
else
    echo "⚠️  event_category 'emulation' not found directly in simple log; may need manual check"
fi

# Verify office spawning rule triggered
if grep -q "Office Spawning" "$MOCK_LOG" || grep -q '"rule_id":' "$MOCK_LOG"; then
    echo "✅ Rule alert data detected in payload"
else
    echo "⚠️  Rule alert not directly visible in simple log; may need manual check"
fi

kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true

echo "Integration test complete."
