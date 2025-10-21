#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--domain DOMAIN] [--email EMAIL]" >&2
  exit 1
}

DOMAIN=""
EMAIL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z "$DOMAIN" && -z "$EMAIL" ]]; then
  usage
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this command" >&2
  exit 1
fi

payload=$(jq -n --arg domain "$DOMAIN" --arg email "$EMAIL" \
  '{domain: ($domain | select(length>0)), email: ($email | select(length>0))}')

curl -s -X POST -H "Content-Type: application/json" -d "$payload" http://localhost:8080/api/scan | jq
