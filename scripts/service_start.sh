#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT_DIR/.tasktmp/sleuth.pid"
LOG_FILE="$ROOT_DIR/.tasktmp/sleuth.log"

mkdir -p "$ROOT_DIR/.tasktmp"

if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    echo "Sleuth service already running (pid $pid)"
    exit 0
  fi
fi

echo "Starting Sleuth service..."
(
  cd "$ROOT_DIR"
  go run main.go
) >"$LOG_FILE" 2>&1 &
pid=$!
echo "$pid" >"$PID_FILE"
sleep 1
echo "Sleuth service started (pid $pid)"
