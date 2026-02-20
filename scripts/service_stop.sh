#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT_DIR/.tasktmp/sleuth.pid"
PORT="${1:-17710}"

stopped=false

# Try PID file first
if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    echo "Stopping Sleuth service (pid $pid)..."
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    echo "Sleuth service stopped."
    stopped=true
  fi
  rm -f "$PID_FILE"
fi

# Fall back to port-based lookup for orphaned processes
orphan="$(lsof -ti :"$PORT" 2>/dev/null || true)"
if [[ -n "$orphan" ]]; then
  echo "Killing orphaned process on port $PORT (pid $orphan)..."
  kill "$orphan" 2>/dev/null || true
  sleep 1
  echo "Orphaned process stopped."
  stopped=true
fi

if [[ "$stopped" == "false" ]]; then
  echo "No Sleuth service found."
fi
