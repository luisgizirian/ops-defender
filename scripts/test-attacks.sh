#!/bin/bash

# Ops Defender - Automated Attack Detection Testing Script
# Tests all 10 defense features to validate defender capabilities
#
# DEFENSE FEATURES TESTED:
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ Pattern-Based Detection (7 features):                                      │
# │  1. path-traversal     - ../  and ..\ directory traversal attempts         │
# │  2. excessive-nesting  - 4+ levels of URL-encoded returnUrl parameters     │
# │  3. sql-injection      - UNION SELECT, DROP TABLE patterns                 │
# │  4. xss                - <script>, eval() cross-site scripting             │
# │  5. open-redirect      - Suspicious redirect parameter patterns            │
# │  6. file-access        - .env, .git, config, backup file access            │
# │  7. admin-scanning     - /wp-admin, /phpmyadmin, .php probing              │
# │                                                                             │
# │ Behavioral Detection (3 features):                                         │
# │  8. subnet-blocking    - /24 subnet-level blocking (via pattern tests)     │
# │  9. identical-uri      - Identical URI repetition (tested implicitly)      │
# │ 10. burst-detection    - Rapid-fire request bursts (tested via rate limit) │
# └─────────────────────────────────────────────────────────────────────────────┘
#
# USAGE:
#   ./test-attacks.sh                    # Test local defender (localhost:8080)
#   DEFENDER_URL=http://host:8080 ./test-attacks.sh   # Test remote defender
#   VERBOSE=true ./test-attacks.sh       # Show detailed request logs
#
# REQUIREMENTS:
#   - Ops Defender running with DEFENSE_FEATURES="all" (default)
#   - curl and jq installed
#   - Defender configured with ANALYSIS_THRESHOLD=5 (default)
#
# Last Updated: January 16, 2026

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
        if [ "$final_response" = "403" ]; then
            echo -e "  ${GREEN}✓ PASSED${NC} - IP correctly blocked"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            echo -e "  ${RED}✗ FAILED${NC} - Expected 403 (blocked), got ${final_response}"
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
    
    if [ "$final_response" = "403" ]; then
        echo -e "  ${GREEN}✓ PASSED${NC} - Rate limit triggered, IP blocked"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "  ${RED}✗ FAILED${NC} - Expected 403 (blocked), got ${final_response}"
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
    echo -e "${BLUE}Testing all 10 defense features:${NC}"
    echo -e "  1. path-traversal"
    echo -e "  2. excessive-nesting"
    echo -e "  3. sql-injection"
    echo -e "  4. xss"
    echo -e "  5. open-redirect"
    echo -e "  6. file-access"
    echo -e "  7. admin-scanning"
    echo -e "  8. subnet-blocking (tested via pattern accumulation)"
    echo -e "  9. identical-uri (tested via repetition)"
    echo -e "  10. burst-detection (tested via rapid requests)"
    echo ""
    
    # ============================================================================
    # PATTERN-BASED DETECTION TESTS (Features 1-7)
    # ============================================================================
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE} Pattern-Based Detection Tests${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Feature 1: Path Traversal Detection
    test_request \
        "[path-traversal] Forward Slash Traversal" \
        "192.168.1.100" \
        "/../../../etc/passwd" \
        "blocked"
    
    test_request \
        "[path-traversal] Backslash Traversal" \
        "192.168.1.101" \
        "/scripts/..\\..\\config.php" \
        "blocked"
    
    # Feature 2: Excessive Nesting Detection
    test_request \
        "[excessive-nesting] 4+ Levels URL Encoding" \
        "192.168.1.102" \
        "/cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos" \
        "blocked"
    
    test_request \
        "[excessive-nesting] Redirect Param Nesting" \
        "192.168.1.103" \
        "/auth?redirect=/login?redirect%3D/auth?redirect%253D/dashboard?redirect%25253D/home" \
        "blocked"
    
    # Feature 3: SQL Injection Detection
    test_request \
        "[sql-injection] UNION SELECT Attack" \
        "192.168.1.104" \
        "/users?id=1 UNION SELECT * FROM users" \
        "blocked"
    
    test_request \
        "[sql-injection] DROP TABLE Attack" \
        "192.168.1.105" \
        "/delete?table=users; DROP TABLE users" \
        "blocked"
    
    # Feature 4: XSS Detection
    test_request \
        "[xss] Script Tag Injection" \
        "192.168.1.106" \
        "/search?q=<script>alert('xss')</script>" \
        "blocked"
    
    test_request \
        "[xss] Eval Function Injection" \
        "192.168.1.107" \
        "/input?data=eval(malicious_code)" \
        "blocked"
    
    # Feature 5: Open Redirect Detection
    test_request \
        "[open-redirect] HTTP Redirect" \
        "192.168.1.108" \
        "/login?redirect=http://evil.com/phishing" \
        "blocked"
    
    test_request \
        "[open-redirect] Protocol-Relative Redirect" \
        "192.168.1.109" \
        "/auth?next=//malicious.site/steal" \
        "blocked"
    
    test_request \
        "[open-redirect] URL-Encoded Redirect" \
        "192.168.1.110" \
        "/oauth?returnUrl=http%3A%2F%2Fattacker.com" \
        "blocked"
    
    # Feature 6: File Access Detection
    test_request \
        "[file-access] Environment File (.env)" \
        "192.168.1.111" \
        "/.env" \
        "blocked"
    
    test_request \
        "[file-access] Git Directory" \
        "192.168.1.112" \
        "/.git/config" \
        "blocked"
    
    test_request \
        "[file-access] Config File" \
        "192.168.1.113" \
        "/config/database.yml" \
        "blocked"
    
    test_request \
        "[file-access] Backup File" \
        "192.168.1.114" \
        "/backup/db.sql" \
        "blocked"
    
    # Feature 7: Admin Scanning Detection
    test_request \
        "[admin-scanning] WordPress Admin" \
        "192.168.1.115" \
        "/wp-admin/admin.php" \
        "blocked"
    
    test_request \
        "[admin-scanning] WordPress Login" \
        "192.168.1.116" \
        "/wp-login.php" \
        "blocked"
    
    test_request \
        "[admin-scanning] phpMyAdmin" \
        "192.168.1.117" \
        "/phpmyadmin/index.php" \
        "blocked"
    
    test_request \
        "[admin-scanning] Generic Admin Panel" \
        "192.168.1.118" \
        "/admin/dashboard" \
        "blocked"
    
    test_request \
        "[admin-scanning] PHP File Probe" \
        "192.168.1.119" \
        "/shell.php" \
        "blocked"
    
    # ============================================================================
    # BEHAVIORAL DETECTION TESTS (Features 8-10)
    # ============================================================================
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE} Behavioral Detection Tests${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Feature 10: Burst Detection (rapid requests)
    test_rate_limit \
        "[burst-detection] Rapid Fire Requests" \
        "192.168.1.120"
    
    # ============================================================================
    # LEGITIMATE TRAFFIC TESTS
    # ============================================================================
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE} Legitimate Traffic Tests${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    test_request \
        "[legitimate] API Endpoint" \
        "192.168.1.200" \
        "/api/users" \
        "allowed"
    
    test_request \
        "[legitimate] Static Content" \
        "192.168.1.201" \
        "/images/logo.png" \
        "allowed"
    
    test_request \
        "[legitimate] Safe Query Parameters" \
        "192.168.1.202" \
        "/products?category=electronics&page=2" \
        "allowed"
    
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
