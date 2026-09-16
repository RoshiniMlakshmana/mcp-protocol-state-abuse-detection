#!/usr/bin/env bash
# Reproduction script for the Track 1 integration lab. Starts the real MCP server, the
# clearly-labeled weakened lab-only stand-in, and the gateway; runs the real MCP client through
# all 5 bounded cases; derives telemetry-contract events from the raw evidence; evaluates the
# existing Track 1 detector (JS reference-oracle model, NOT a query engine) against them; then
# stops the three lab processes. Does not touch Splunk in any way.
#
# Usage: bash run-lab.sh
set -euo pipefail
cd "$(dirname "$0")"

PORTS=(4000 4001 4002)
for port in "${PORTS[@]}"; do
  pid=$(netstat -ano 2>/dev/null | grep "127.0.0.1:$port" | grep LISTENING | awk '{print $5}' | head -1 || true)
  if [ -n "${pid:-}" ]; then
    echo "[run-lab] port $port already in use by pid $pid -- stopping it first"
    taskkill //PID "$pid" //F >/dev/null 2>&1 || true
  fi
done

rm -rf evidence
mkdir -p evidence

LOG_DIR="${TMPDIR:-/tmp}/track1-lab-logs"
mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="./.lab-logs" && mkdir -p "$LOG_DIR"

TRACK1_LAB_SERVER_PORT=4001 node server.js > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
TRACK1_LAB_WEAKENED_PORT=4002 node weakened-server.js > "$LOG_DIR/weakened.log" 2>&1 &
WEAKENED_PID=$!
sleep 1
TRACK1_LAB_GATEWAY_PORT=4000 TRACK1_LAB_SERVER_PORT=4001 TRACK1_LAB_WEAKENED_PORT=4002 node gateway.js > "$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
sleep 1

cleanup() {
  kill "$SERVER_PID" "$WEAKENED_PID" "$GATEWAY_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[run-lab] servers up (logs in $LOG_DIR); running client through all 5 bounded cases"
node client-runner.js

echo "[run-lab] deriving telemetry-contract events from raw evidence"
node lib/audit.js

echo "[run-lab] evaluating the existing Track 1 detector (JS model, not a query engine)"
node evaluate-detector.js

echo "[run-lab] done -- see evidence/ for client-observed-cases.json, raw/*.json, telemetry-events.json, detector-evaluation.json"
