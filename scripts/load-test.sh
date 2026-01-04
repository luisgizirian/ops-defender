#!/bin/bash

# Ops Defender - Load Testing Script
# Simulates realistic traffic with occasional attack patterns

set -e

# Configuration
DEFENDER_URL="${DEFENDER_URL:-http://localhost:8080}"
DURATION="${DURATION:-60}"  # Test duration in seconds
REQUESTS_PER_SECOND="${RPS:-10}"
ATTACK_RATIO="${ATTACK_RATIO:-0.1}"  # 10% of requests are attacks

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            Ops DEFENDER - LOAD TEST SCRIPT                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Target:           ${YELLOW}${DEFENDER_URL}${NC}"
echo -e "Duration:         ${YELLOW}${DURATION}s${NC}"
echo -e "Requests/sec:     ${YELLOW}${REQUESTS_PER_SECOND}${NC}"
echo -e "Attack ratio:     ${YELLOW}$(echo "$ATTACK_RATIO * 100" | bc)%${NC}"
echo ""

# Legitimate URIs
LEGITIMATE_URIS=(
    "/api/users"
    "/api/products"
    "/api/orders"
    "/dashboard"
    "/profile"
    "/search?q=laptop"
    "/category/electronics"
    "/product/123"
    "/checkout"
    "/api/stats"
)

# Attack URIs
ATTACK_URIS=(
    "/../../../etc/passwd"
    "/wp-admin/admin.php"
    "/users?id=1 UNION SELECT * FROM users"
    "/<script>alert(1)</script>"
    "/login?redirect=http://evil.com"
    "/.env"
    "/.git/config"
    "/phpmyadmin"
    "/shell.php"
    "/admin?next=//malicious.site"
)

# Generate random IP
generate_ip() {
    echo "10.0.$((RANDOM % 256)).$((RANDOM % 256))"
}

# Generate random legitimate IP (for normal users)
generate_legitimate_ip() {
    # Use a smaller pool for legitimate users
    echo "10.1.$((RANDOM % 10)).$((RANDOM % 50))"
}

# Send request
send_request() {
    local ip="$1"
    local uri="$2"
    
    curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Real-IP: ${ip}" \
        -H "X-Original-URI: ${uri}" \
        "${DEFENDER_URL}/check" 2>/dev/null
}

# Main load test
run_load_test() {
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0
    local legitimate_count=0
    local attack_count=0
    local blocked_count=0
    
    echo -e "${GREEN}Starting load test...${NC}"
    echo ""
    
    while [ $(date +%s) -lt $end_time ]; do
        # Determine if this request should be an attack
        if (( $(echo "$RANDOM / 32767 < $ATTACK_RATIO" | bc -l) )); then
            # Attack request
            ip=$(generate_ip)
            uri="${ATTACK_URIS[$RANDOM % ${#ATTACK_URIS[@]}]}"
            attack_count=$((attack_count + 1))
        else
            # Legitimate request
            ip=$(generate_legitimate_ip)
            uri="${LEGITIMATE_URIS[$RANDOM % ${#LEGITIMATE_URIS[@]}]}"
            legitimate_count=$((legitimate_count + 1))
        fi
        
        # Send request in background
        status=$(send_request "$ip" "$uri")
        
        if [ "$status" = "404" ]; then
            blocked_count=$((blocked_count + 1))
        fi
        
        request_count=$((request_count + 1))
        
        # Print progress every 50 requests
        if [ $((request_count % 50)) -eq 0 ]; then
            elapsed=$(($(date +%s) - start_time))
            rps=$((request_count / elapsed))
            echo -e "${BLUE}Progress:${NC} ${request_count} requests | ${rps} req/s | Blocked: ${blocked_count}"
        fi
        
        # Control request rate
        sleep $(echo "1 / $REQUESTS_PER_SECOND" | bc -l)
    done
    
    echo ""
    echo -e "${GREEN}Load test complete!${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Results:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Total Requests:       ${request_count}"
    echo -e "  Legitimate:           ${legitimate_count}"
    echo -e "  Attack Attempts:      ${attack_count}"
    echo -e "  Blocked Requests:     ${blocked_count}"
    echo -e "  Block Rate:           $(echo "scale=2; $blocked_count * 100 / $request_count" | bc)%"
    echo ""
    
    # Show defender stats
    echo -e "${BLUE}Defender Statistics:${NC}"
    curl -s "${DEFENDER_URL}/stats" | jq '.' 2>/dev/null
}

# Check if defender is running
echo -n "Checking if Ops Defender is running... "
if curl -s -f "${DEFENDER_URL}/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ OK${NC}"
    echo ""
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "Please start the defender first."
    exit 1
fi

# Run the test
run_load_test
