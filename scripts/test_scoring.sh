#!/bin/bash
# Test script to demonstrate Sleuth threat intelligence scoring API

set -e

BASE_URL="${SLEUTH_URL:-http://localhost:8080}"

echo "Testing Sleuth Threat Intelligence Scoring API"
echo "=============================================="
echo ""

# Check if service is running
if ! curl -sf "$BASE_URL/api/health" > /dev/null 2>&1; then
    echo "Error: Sleuth service is not running at $BASE_URL"
    echo "Start it with: task service:start && task service:wait"
    exit 1
fi

echo "Service is healthy"
echo ""

# Test 1: Domain only
echo "Test 1: Domain scoring"
echo "-----------------------"
curl -s -X POST "$BASE_URL/api/intel/check" \
    -H "Content-Type: application/json" \
    -d '{"domain": "example.com"}' | jq '{
    domain: .data.domain,
    score: .data.score,
    risk_level: .data.risk_level,
    recommendation: .data.recommendation,
    reasons: .data.reasons,
    flags: .data.flags
}'
echo ""

# Test 2: Email only
echo "Test 2: Email scoring"
echo "---------------------"
curl -s -X POST "$BASE_URL/api/intel/check" \
    -H "Content-Type: application/json" \
    -d '{"email": "user@example.com"}' | jq '{
    email: .data.email,
    score: .data.score,
    risk_level: .data.risk_level,
    recommendation: .data.recommendation,
    reasons: .data.reasons,
    flags: .data.flags
}'
echo ""

# Test 3: Both email and domain
echo "Test 3: Email and domain scoring"
echo "---------------------------------"
curl -s -X POST "$BASE_URL/api/intel/check" \
    -H "Content-Type: application/json" \
    -d '{"email": "user@example.com", "domain": "example.com"}' | jq '{
    email: .data.email,
    domain: .data.domain,
    score: .data.score,
    risk_level: .data.risk_level,
    recommendation: .data.recommendation,
    reasons: .data.reasons,
    flags: .data.flags
}'
echo ""

# Test 4: Check for feeds not hydrated
echo "Test 4: Error handling (feeds not hydrated)"
echo "--------------------------------------------"
curl -s -X POST "$BASE_URL/api/intel/check" \
    -H "Content-Type: application/json" \
    -d '{"domain": "test.com"}' | jq '{
    success: .success,
    error: .error
}'
echo ""

echo "Testing complete!"
echo ""
echo "To hydrate threat intelligence feeds, run:"
echo "  task call:intel-hydrate"
echo ""
echo "For full response details, remove the jq filter from the curl commands above."
