#!/bin/bash

# Ops Defender - Automated Attack Detection Testing Script
# Tests various attack patterns to validate defender capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFENDER_URL="${DEFENDER_URL:-http://localhost:8080}"
TEST_DELAY="${TEST_DELAY:-0.5}"
VERBOSE="${VERBOSE:-false}"

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Ops DEFENDER - ATTACK DETECTION TEST SUITE           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Target: ${YELLOW}${DEFENDER_URL}${NC}"
echo -e "Test Delay: ${YELLOW}${TEST_DELAY}s${NC}"
echo ""

# Function to check if defender is running
check_defender() {
    echo -n "Checking if Ops Defender is running... "
    if curl -s -f "${DEFENDER_URL}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo -e "${RED}Error: Ops Defender is not responding at ${DEFENDER_URL}${NC}"
        echo "Please start the defender first:"
        echo "  docker-compose up -d"
        echo "  or"
        echo "  ./ops-defender"
        exit 1
    fi
}

# Function to send test request
test_request() {
    local test_name="$1"
    local ip="$2"
    local uri="$3"
    local expected_after_threshold="$4"  # "blocked" or "allowed"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "\n${YELLOW}Test ${TOTAL_TESTS}: ${test_name}${NC}"
    echo -e "  IP: ${ip}"
    echo -e "  URI: ${uri}"
    
    # Send ANALYSIS_THRESHOLD requests (default 5)
    local threshold=5
    local last_status=""
    
    for i in $(seq 1 $threshold); do
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "X-Real-IP: ${ip}" \
            -H "X-Original-URI: ${uri}" \
            "${DEFENDER_URL}/check")
        
        last_status=$response
        
        if [ "$VERBOSE" = "true" ]; then
            echo -e "    Request $i: ${response}"
        fi
        
        sleep $TEST_DELAY
    done
    
    # Wait a bit for analysis to complete
    sleep 1
    
    # Send one more request to check if blocked
    final_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Real-IP: ${ip}" \
        -H "X-Original-URI: ${uri}" \
        "${DEFENDER_URL}/check")
    
    echo -e "  Final status after ${threshold} requests: ${final_response}"
    
    # Verify expected behavior
    if [ "$expected_after_threshold" = "blocked" ]; then
        if [ "$final_response" = "404" ]; then
            echo -e "  ${GREEN}✓ PASSED${NC} - IP correctly blocked"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            echo -e "  ${RED}✗ FAILED${NC} - Expected 404 (blocked), got ${final_response}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        if [ "$final_response" = "200" ]; then
            echo -e "  ${GREEN}✓ PASSED${NC} - Request correctly allowed"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            echo -e "  ${RED}✗ FAILED${NC} - Expected 200 (allowed), got ${final_response}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    fi
}

# Function to test rapid requests (rate limiting)
test_rate_limit() {
    local test_name="$1"
    local ip="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "\n${YELLOW}Test ${TOTAL_TESTS}: ${test_name}${NC}"
    echo -e "  IP: ${ip}"
    echo -e "  Sending 10 rapid requests..."
    
    # Send 10 requests as fast as possible
    for i in $(seq 1 10); do
        curl -s -o /dev/null \
            -H "X-Real-IP: ${ip}" \
            -H "X-Original-URI: /api/data" \
            "${DEFENDER_URL}/check"
        
        if [ "$VERBOSE" = "true" ]; then
            echo -e "    Rapid request $i sent"
        fi
    done
    
    sleep 1
    
    # Check if blocked
    final_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Real-IP: ${ip}" \
        -H "X-Original-URI: /api/data" \
        "${DEFENDER_URL}/check")
    
    echo -e "  Final status: ${final_response}"
    
    if [ "$final_response" = "404" ]; then
        echo -e "  ${GREEN}✓ PASSED${NC} - Rate limit triggered, IP blocked"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "  ${RED}✗ FAILED${NC} - Expected 404 (blocked), got ${final_response}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to get stats
show_stats() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Current Defender Statistics:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    
    stats=$(curl -s "${DEFENDER_URL}/stats")
    echo "$stats" | jq '.' 2>/dev/null || echo "$stats"
}

# Main test execution
main() {
    check_defender
    
    echo -e "\n${BLUE}Starting attack detection tests...${NC}"
    
    # Test 1: Path Traversal
    test_request \
        "Path Traversal Attack" \
        "192.168.1.100" \
        "/../../../etc/passwd" \
        "blocked"
    
    # Test 2: SQL Injection
    test_request \
        "SQL Injection Attack" \
        "192.168.1.101" \
        "/users?id=1 UNION SELECT * FROM users" \
        "blocked"
    
    # Test 3: XSS Attempt
    test_request \
        "XSS Attack" \
        "192.168.1.102" \
        "/search?q=<script>alert('xss')</script>" \
        "blocked"
    
    # Test 4: WordPress Admin Access
    test_request \
        "WordPress Admin Scan" \
        "192.168.1.103" \
        "/wp-admin/admin.php" \
        "blocked"
    
    # Test 5: Open Redirect Attack
    test_request \
        "Open Redirect Attack" \
        "192.168.1.104" \
        "/login?redirect=http://evil.com/phishing" \
        "blocked"
    
    # Test 6: Protocol Relative Redirect
    test_request \
        "Protocol-Relative Redirect" \
        "192.168.1.105" \
        "/auth?next=//malicious.site/steal" \
        "blocked"
    
    # Test 7: Environment File Access
    test_request \
        "Environment File Access" \
        "192.168.1.106" \
        "/.env" \
        "blocked"
    
    # Test 8: Git Directory Access
    test_request \
        "Git Directory Access" \
        "192.168.1.107" \
        "/.git/config" \
        "blocked"
    
    # Test 9: phpMyAdmin Scan
    test_request \
        "phpMyAdmin Scan" \
        "192.168.1.108" \
        "/phpmyadmin/index.php" \
        "blocked"
    
    # Test 10: PHP File Probe
    test_request \
        "PHP File Probe" \
        "192.168.1.109" \
        "/shell.php" \
        "blocked"
    
    # Test 11: Legitimate Request
    test_request \
        "Legitimate Request" \
        "192.168.1.200" \
        "/api/users" \
        "allowed"
    
    # Test 12: Rate Limiting
    test_rate_limit \
        "Rate Limit Detection" \
        "192.168.1.110"
    
    # Show current stats
    show_stats
    
    # Print summary
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                        TEST SUMMARY                            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Total Tests:  ${TOTAL_TESTS}"
    echo -e "  ${GREEN}Passed:       ${PASSED_TESTS}${NC}"
    echo -e "  ${RED}Failed:       ${FAILED_TESTS}${NC}"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        echo ""
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Please review the output above.${NC}"
        echo ""
        exit 1
    fi
}

# Run main function
main
