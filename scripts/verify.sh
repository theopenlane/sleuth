#!/bin/bash
set -e

BASE_URL="${SLEUTH_URL:-http://localhost:8080}"

echo "Verifying Sleuth service endpoints"
echo "=================================="
echo ""

# Test health endpoint
echo "Testing health endpoint..."
HEALTH=$(curl -sf "$BASE_URL/api/health" | jq -r '.status')
if [ "$HEALTH" != "healthy" ]; then
    echo "FAIL: Health check failed"
    exit 1
fi
echo "PASS: Health endpoint"
echo ""

# Test scan endpoint
echo "Testing scan endpoint..."
SCAN_SUCCESS=$(curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"domain":"example.com"}' \
    "$BASE_URL/api/scan" | jq -r '.success')
if [ "$SCAN_SUCCESS" != "true" ]; then
    echo "FAIL: Scan endpoint failed"
    exit 1
fi
echo "PASS: Scan endpoint"
echo ""

# Test intel check endpoint (should return not hydrated error with 409 status)
echo "Testing intel check endpoint..."
INTEL_ERROR=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"domain":"example.com"}' \
    "$BASE_URL/api/intel/check" | jq -r '.error')
if [ "$INTEL_ERROR" != "threat intelligence feeds have not been hydrated" ]; then
    echo "FAIL: Intel check endpoint unexpected response"
    exit 1
fi
echo "PASS: Intel check endpoint"
echo ""

echo "All verification tests passed"
