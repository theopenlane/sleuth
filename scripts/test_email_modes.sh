#!/bin/bash
set -e

BASE_URL="${SLEUTH_URL:-http://localhost:8080}"

echo "=== Testing Email Scan Modes ==="
echo

echo "1. Domain-only scan (full infrastructure):"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' \
  "${BASE_URL}/api/scan" | jq -c '{success, domain: .data.domain, email: .data.email, results: (.data.results | length), has_intel: (.data.intel_score != null)}'
echo

echo "2. Email-only check (intel feeds, fast):"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}' \
  "${BASE_URL}/api/scan" | jq -c '{success, domain: .data.domain, email: .data.email, results: (.data.results | length), has_intel: (.data.intel_score != null), score: .data.intel_score.score}'
echo

echo "3. Email + domain scan (intel + infrastructure):"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","scan_domain":true}' \
  "${BASE_URL}/api/scan" | jq -c '{success, domain: .data.domain, email: .data.email, results: (.data.results | length), has_intel: (.data.intel_score != null), score: .data.intel_score.score}'
echo

echo "=== All modes tested ==="
