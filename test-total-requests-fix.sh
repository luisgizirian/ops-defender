#!/bin/bash
# Test script to verify totalRequests >= blockedRequests fix

set -e

echo "Testing totalRequests counter fix..."
echo ""

# Start ops-defender in background
echo "Starting ops-defender..."
./ops-defender &
PID=$!
sleep 2

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $PID 2>/dev/null || true
}
trap cleanup EXIT

# Send some legitimate requests
echo "1. Sending 5 legitimate requests..."
for i in {1..5}; do
    curl -s -H "X-Real-IP: 192.168.1.100" \
         -H "X-Original-URI: /api/products" \
         http://localhost:8080/check > /dev/null
done

# Trigger blocking by sending malicious request
echo "2. Sending malicious request to trigger block..."
for i in {1..6}; do
    curl -s -H "X-Real-IP: 192.168.1.200" \
         -H "X-Original-URI: /../etc/passwd" \
         http://localhost:8080/check > /dev/null
    sleep 0.2
done

# Send more requests from blocked IP
echo "3. Sending 10 requests from blocked IP..."
for i in {1..10}; do
    curl -s -H "X-Real-IP: 192.168.1.200" \
         -H "X-Original-URI: /api/users" \
         http://localhost:8080/check > /dev/null
done

# Get stats
echo "4. Checking stats..."
STATS=$(curl -s http://localhost:8080/stats)
echo "$STATS" | jq .

TOTAL=$(echo "$STATS" | jq -r '.total_requests')
BLOCKED=$(echo "$STATS" | jq -r '.blocked_requests')

echo ""
echo "Results:"
echo "  Total Requests:   $TOTAL"
echo "  Blocked Requests: $BLOCKED"
echo ""

if [ "$TOTAL" -ge "$BLOCKED" ]; then
    echo "✅ PASS: Total requests ($TOTAL) >= Blocked requests ($BLOCKED)"
    exit 0
else
    echo "❌ FAIL: Total requests ($TOTAL) < Blocked requests ($BLOCKED)"
    echo "This should be impossible!"
    exit 1
fi
