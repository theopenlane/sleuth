#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT_DIR/.tasktmp/sleuth.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No Sleuth pid file found."
  exit 0
fi

pid="$(cat "$PID_FILE")"
if kill -0 "$pid" 2>/dev/null; then
  echo "Stopping Sleuth service (pid $pid)..."
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  echo "Sleuth service stopped."
else
  echo "No running service found for pid $pid"
fi

rm -f "$PID_FILE"
