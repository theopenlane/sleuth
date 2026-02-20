#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://localhost:17710/api/health}"
RETRIES="${2:-20}"
SLEEP_SECONDS="${3:-1}"

count=0
while ! curl -sf "$URL" >/dev/null; do
  count=$((count + 1))
  if [[ "$count" -ge "$RETRIES" ]]; then
    echo "Service did not become ready after $RETRIES attempts" >&2
    exit 1
  fi
  sleep "$SLEEP_SECONDS"
done

echo "Service is healthy at $URL"
