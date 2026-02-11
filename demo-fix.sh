#!/bin/bash
# Demo script showing the fix for blocked IPs request count

echo "=== Demonstrating the fix for blocked IPs request count ==="
echo ""

# Create unique log file for this demo instance
LOG_FILE=$(mktemp /tmp/ops-defender-demo.XXXXXX.log)

# Start ops-defender in background
echo "Starting ops-defender..."
PORT=8080 ANALYSIS_THRESHOLD=3 ./ops-defender > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 2

echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Send malicious requests
TEST_IP="10.0.0.123"
echo "Sending 3 malicious requests from IP $TEST_IP..."
for i in {1..3}; do
  curl -s -H "X-Real-IP: $TEST_IP" \
       -H "X-Original-URI: /wp-admin" \
       http://localhost:8080/check > /dev/null
  echo "  ✓ Request $i sent"
done

echo ""
echo "Waiting for analysis worker to block the IP..."
sleep 1

# Check stats
echo ""
echo "=== Stats Response ==="
curl -s http://localhost:8080/stats | python3 -m json.tool | grep -A 7 '"top_ips"'

echo ""
echo "=== Key Finding ==="
REQUESTS=$(curl -s http://localhost:8080/stats | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['top_ips'][0]['requests'] if data['top_ips'] else 'N/A')")
echo "Blocked IP shows: $REQUESTS requests"
if [ "$REQUESTS" = "3" ]; then
  echo "✓ SUCCESS: Request count is correctly showing 3 (not 0!)"
else
  echo "✗ FAILED: Expected 3 requests, got $REQUESTS"
fi

# Cleanup
echo ""
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null
rm -f "$LOG_FILE"
echo "✓ Demo complete"
