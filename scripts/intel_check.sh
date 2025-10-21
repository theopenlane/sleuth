#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: intel_check.sh [--domain DOMAIN] [--email EMAIL] [--types TYPE1,TYPE2] [--resolve-ips true|false]
At least one of --domain or --email must be provided.
EOF
  exit 1
}

DOMAIN=""
EMAIL=""
TYPES=""
RESOLVE="false"

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
    --types)
      TYPES="${2:-}"
      shift 2
      ;;
    --resolve-ips)
      RESOLVE="${2:-false}"
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

payload=$(jq -n \
  --arg domain "$DOMAIN" \
  --arg email "$EMAIL" \
  --arg resolve "$RESOLVE" \
  --arg types "$TYPES" '
    {
      domain: ($domain | select(length>0)),
      email: ($email | select(length>0)),
      include_resolved_ips: ($resolve | test("(?i)^(1|true|yes)$"))
    } + (if $types | length > 0 then {indicator_types: ($types | split(","))} else {} end)
  ')

curl -s -X POST -H "Content-Type: application/json" -d "$payload" http://localhost:8080/api/intel/check | jq
