#!/bin/bash
# Test script for IPv6 support verification

set -e

echo "=== IPv6 Support Test ==="
echo

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq is not installed. Stats output will be shown in raw JSON format."
    JQ_AVAILABLE=false
else
    JQ_AVAILABLE=true
fi

# Start the service in background
./ops-defender &
SERVER_PID=$!
echo "Started ops-defender with PID $SERVER_PID"

# Wait for server to start
sleep 2

# Function to test IP extraction
test_ip() {
    local ip=$1
    local uri=$2
    local description=$3
    
    echo "Testing: $description"
    echo "  IP: $ip"
    echo "  URI: $uri"
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "X-Real-IP: $ip" \
        -H "X-Original-URI: $uri" \
        http://localhost:8080/check)
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        echo "  ✓ Request allowed (HTTP $http_code)"
    else
        echo "  ✗ Request blocked (HTTP $http_code)"
    fi
    echo
}

echo "--- Testing IPv4 Addresses ---"
test_ip "192.168.1.100" "/api/users" "IPv4 - Legitimate request"
test_ip "10.0.0.50" "/products" "IPv4 - Another legitimate request"

echo "--- Testing IPv6 Addresses ---"
test_ip "2001:db8::1" "/api/users" "IPv6 - Standard format"
test_ip "2001:0db8:85a3:0000:0000:8a2e:0370:7334" "/api/data" "IPv6 - Full format"
test_ip "::1" "/api/local" "IPv6 - Loopback"
test_ip "fe80::1" "/api/link-local" "IPv6 - Link-local"
test_ip "2001:db8:85a3::8a2e:370:7334" "/api/compressed" "IPv6 - Compressed format"

echo "--- Testing IPv6 with Suspicious Patterns ---"
test_ip "2001:db8::2" "/wp-admin" "IPv6 - WordPress admin (1st request)"
test_ip "2001:db8::2" "/wp-admin" "IPv6 - WordPress admin (2nd request)"
test_ip "2001:db8::2" "/wp-admin" "IPv6 - WordPress admin (3rd request)"
test_ip "2001:db8::2" "/wp-admin" "IPv6 - WordPress admin (4th request)"
test_ip "2001:db8::2" "/wp-admin" "IPv6 - WordPress admin (5th request)"

echo "Waiting for analysis..."
sleep 2

test_ip "2001:db8::2" "/api/test" "IPv6 - Should be blocked after analysis"

echo "--- Checking Stats ---"
if [ "$JQ_AVAILABLE" = true ]; then
    curl -s http://localhost:8080/stats | jq '.'
else
    curl -s http://localhost:8080/stats
    echo
fi

# Cleanup
echo
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || {
    echo "Warning: Failed to gracefully stop server (PID $SERVER_PID)"
}
wait $SERVER_PID 2>/dev/null || true

echo
echo "=== IPv6 Test Complete ==="
