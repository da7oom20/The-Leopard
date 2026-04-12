#!/bin/bash
# The Leopard - Security Test Suite
# Manual security tests - run with: bash run-security-tests.sh

API_URL="${TEST_API_URL:-http://127.0.0.1:3005/api}"
PASS=0
FAIL=0
WARN=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================"
echo -e "${BLUE}  The Leopard - Security Test Suite${NC}"
echo "  API URL: $API_URL"
echo "========================================"
echo ""
echo -e "${YELLOW}⚠ This runs security tests against your API${NC}"
echo -e "${YELLOW}  Press Ctrl+C to cancel, or wait 3 seconds...${NC}"
sleep 3
echo ""

# Helper function for security tests
security_test() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" == "$expected" ] || [[ "$expected" == *"$actual"* ]]; then
        echo -e "${GREEN}✓ SECURE${NC}: $name"
        ((PASS++))
    else
        echo -e "${RED}✗ RISK${NC}: $name (got: $actual)"
        ((FAIL++))
    fi
}

warn_test() {
    local name="$1"
    echo -e "${YELLOW}⚠ WARN${NC}: $name"
    ((WARN++))
}

# Wait for API
echo "Checking API availability..."
for i in {1..10}; do
    if curl --noproxy '*' -s "$API_URL/setup/status" > /dev/null 2>&1; then
        echo -e "${GREEN}API is ready!${NC}"
        echo ""
        break
    fi
    if [ $i -eq 10 ]; then
        echo -e "${RED}API not responding. Is the backend running?${NC}"
        exit 1
    fi
    sleep 1
done

# ============================================
echo "--- SQL Injection Tests ---"
# ============================================

# Test 1: SQL injection in username
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"'\'' OR '\''1'\''='\''1","password":"test"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$status" == "400" || "$status" == "401" || "$status" == "429" ]]; then
    if [[ ! "$body" =~ [Ss]ql|[Ss]yntax|[Qq]uery ]]; then
        security_test "SQL injection in username blocked" "pass" "pass"
    else
        security_test "SQL injection in username blocked" "no sql error" "sql error exposed"
    fi
else
    security_test "SQL injection in username blocked" "400/401" "$status"
fi
sleep 0.3

# Test 2: SQL injection in password
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"'\'' OR '\''1'\''='\''1"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$status" == "400" || "$status" == "401" || "$status" == "429" ]]; then
    security_test "SQL injection in password blocked" "pass" "pass"
else
    security_test "SQL injection in password blocked" "400/401" "$status"
fi
sleep 0.3

# Test 3: DROP TABLE attempt
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"'\''; DROP TABLE users; --","password":"test"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "400" || "$status" == "401" || "$status" == "429" ]]; then
    security_test "DROP TABLE injection blocked" "pass" "pass"
else
    security_test "DROP TABLE injection blocked" "400/401" "$status"
fi
sleep 0.3

# ============================================
echo ""
echo "--- Authentication Security ---"
# ============================================

# Test 4: Invalid JWT token
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL/admin/users" \
    -H "Authorization: Bearer invalid.token.here" 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "401" || "$status" == "403" ]]; then
    security_test "Invalid JWT rejected" "pass" "pass"
else
    security_test "Invalid JWT rejected" "401/403" "$status"
fi
sleep 0.3

# Test 5: Empty auth header
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL/admin/users" \
    -H "Authorization: Bearer " 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "401" || "$status" == "403" ]]; then
    security_test "Empty JWT rejected" "pass" "pass"
else
    security_test "Empty JWT rejected" "401/403" "$status"
fi
sleep 0.3

# Test 6: No auth to admin endpoint
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL/admin/users" 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "401" || "$status" == "403" ]]; then
    security_test "Admin endpoints require auth" "pass" "pass"
else
    security_test "Admin endpoints require auth" "401/403" "$status"
fi
sleep 0.3

# ============================================
echo ""
echo "--- Authorization Tests ---"
# ============================================

# Test 7: Cannot create admin without auth
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/admin/users" \
    -H "Content-Type: application/json" \
    -d '{"username":"hacker","password":"hacked123","role":"admin"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "401" || "$status" == "403" ]]; then
    security_test "Cannot create users without auth" "pass" "pass"
else
    security_test "Cannot create users without auth" "401/403" "$status"
fi
sleep 0.3

# Test 8: Cannot delete users without auth
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X DELETE "$API_URL/admin/users/1" 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" == "401" || "$status" == "403" ]]; then
    security_test "Cannot delete users without auth" "pass" "pass"
else
    security_test "Cannot delete users without auth" "401/403" "$status"
fi
sleep 0.3

# ============================================
echo ""
echo "--- Input Validation ---"
# ============================================

# Test 9: Path traversal in export
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET \
    "$API_URL/../../../etc/passwd" 2>/dev/null)
status=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ ! "$body" =~ root:|bin:|daemon: ]]; then
    security_test "Path traversal blocked" "pass" "pass"
else
    security_test "Path traversal blocked" "no file contents" "file contents exposed"
fi
sleep 0.3

# Test 10: Null byte injection
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin\u0000","password":"test"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)

if [[ "$status" != "500" ]]; then
    security_test "Null byte handled safely" "pass" "pass"
else
    security_test "Null byte handled safely" "not 500" "$status"
fi
sleep 0.3

# ============================================
echo ""
echo "--- Rate Limiting ---"
# ============================================

# Test 11: Rate limiting active
rate_limited=0
for i in {1..12}; do
    response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"test'$i'","password":"test"}' 2>/dev/null)
    status=$(echo "$response" | tail -n1)
    if [[ "$status" == "429" ]]; then
        ((rate_limited++))
    fi
done

if [[ $rate_limited -gt 0 ]]; then
    security_test "Rate limiting active" "pass" "pass"
else
    warn_test "Rate limiting may not be active (no 429 responses in 12 requests)"
fi

# ============================================
echo ""
echo "--- Sensitive Data Protection ---"
# ============================================

# Test 12: No password in user response
response=$(curl --noproxy '*' -s "$API_URL/setup/status" 2>/dev/null)

if [[ ! "$response" =~ passwordHash|password.*: ]]; then
    security_test "No password hash exposed" "pass" "pass"
else
    security_test "No password hash exposed" "no hash" "hash exposed"
fi

# Test 13: No stack traces in errors
response=$(curl --noproxy '*' -s -X POST "$API_URL/upload" \
    -H "Content-Type: application/json" \
    -d 'invalid' 2>/dev/null)

if [[ ! "$response" =~ "at "[A-Za-z]|node_modules|/app/ ]]; then
    security_test "No stack traces in errors" "pass" "pass"
else
    security_test "No stack traces in errors" "no traces" "traces exposed"
fi

# ============================================
echo ""
echo "========================================"
echo -e "  ${BLUE}Security Test Results${NC}"
echo "========================================"
echo -e "  ${GREEN}Secure: $PASS${NC}"
echo -e "  ${RED}At Risk: $FAIL${NC}"
echo -e "  ${YELLOW}Warnings: $WARN${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}⚠ Security issues detected! Review the failures above.${NC}"
    exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "${YELLOW}✓ No critical issues, but review warnings.${NC}"
    exit 0
else
    echo -e "${GREEN}✓ All security tests passed!${NC}"
    exit 0
fi
