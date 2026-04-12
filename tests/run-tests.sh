#!/bin/bash
# The Leopard - Quick API Test Script
# Tests core functionality without npm dependencies

API_URL="${TEST_API_URL:-http://127.0.0.1:3005/api}"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  The Leopard - API Test Suite"
echo "  API URL: $API_URL"
echo "========================================"
echo ""

# Wait for API to be ready
echo "Checking API availability..."
for i in {1..30}; do
    if curl --noproxy '*' -s "$API_URL/setup/status" > /dev/null 2>&1; then
        echo -e "${GREEN}API is ready!${NC}"
        echo ""
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}API not responding after 30 seconds. Is the backend running?${NC}"
        echo "Try: sudo docker restart ioc-backend-v5"
        exit 1
    fi
    echo -n "."
    sleep 1
done

# Login to get auth token
echo "Authenticating..."
AUTH_USER="${TEST_ADMIN_USER:-admin}"
AUTH_PASS="${TEST_ADMIN_PASS:-admin123}"
LOGIN_RESPONSE=$(curl --noproxy '*' -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$AUTH_USER\",\"password\":\"$AUTH_PASS\"}" 2>/dev/null)

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}Authenticated successfully${NC}"
    AUTH_HEADER="Authorization: Bearer $TOKEN"
else
    echo -e "${YELLOW}Warning: Could not authenticate. Protected endpoint tests will fail.${NC}"
    AUTH_HEADER=""
fi
echo ""

# Test function (no auth)
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local data="$5"

    if [ "$method" == "GET" ]; then
        response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL$endpoint" 2>/dev/null)
    else
        response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null)
    fi

    status=$(echo "$response" | tail -n1)

    if [ "$status" == "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name (HTTP $status)"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name (expected $expected_status, got $status)"
        ((FAIL++))
    fi
    sleep 0.3
}

# Test function (with auth)
test_endpoint_auth() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local data="$5"

    if [ -z "$TOKEN" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC}: $name (no auth token)"
        return
    fi

    if [ "$method" == "GET" ]; then
        response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL$endpoint" \
            -H "$AUTH_HEADER" 2>/dev/null)
    else
        response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL$endpoint" \
            -H "Content-Type: application/json" \
            -H "$AUTH_HEADER" \
            -d "$data" 2>/dev/null)
    fi

    status=$(echo "$response" | tail -n1)

    if [ "$status" == "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name (HTTP $status)"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name (expected $expected_status, got $status)"
        ((FAIL++))
    fi
    sleep 0.3
}

# Test auth endpoint returns proper error
test_auth_reject() {
    local name="$1"
    local endpoint="$2"

    response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X GET "$API_URL$endpoint" 2>/dev/null)
    status=$(echo "$response" | tail -n1)

    if [ "$status" == "401" ] || [ "$status" == "403" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name (HTTP $status)"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name (expected 401/403, got $status)"
        ((FAIL++))
    fi
    sleep 0.3
}

# Test POST endpoint rejects without auth
test_post_auth_reject() {
    local name="$1"
    local endpoint="$2"
    local data="${3:-{}}"

    response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data" 2>/dev/null)
    status=$(echo "$response" | tail -n1)

    if [ "$status" == "401" ] || [ "$status" == "403" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name (HTTP $status)"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name (expected 401/403, got $status)"
        ((FAIL++))
    fi
    sleep 0.3
}

echo "--- Health Checks ---"
test_endpoint "API is accessible" "GET" "/setup/status" "200"
test_endpoint_auth "Database connection (with auth)" "POST" "/setup/test-db" "200"

echo ""
echo "--- Public Endpoints ---"
test_endpoint "GET /clients" "GET" "/clients" "200"
test_endpoint "GET /ti-sources" "GET" "/ti-sources" "200"
test_endpoint "GET /setup/status" "GET" "/setup/status" "200"

echo ""
echo "--- Auth Required (should reject without token) ---"
test_auth_reject "GET /repo requires auth" "/repo"
test_post_auth_reject "POST /hunt requires auth" "/hunt"
test_auth_reject "GET /admin/api-keys requires auth" "/admin/api-keys"
test_auth_reject "GET /admin/users requires auth" "/admin/users"
test_auth_reject "GET /admin/ti-sources requires auth" "/admin/ti-sources"
test_auth_reject "GET /recon/mappings/:id requires auth" "/recon/mappings/1"

echo ""
echo "--- Protected Endpoints (with auth) ---"
test_endpoint_auth "GET /repo" "GET" "/repo" "200"
test_endpoint_auth "POST /hunt (empty body)" "POST" "/hunt" "400" '{}'

echo ""
echo "--- Authentication ---"
test_endpoint "Login with empty credentials" "POST" "/auth/login" "400" '{}'
response=$(curl --noproxy '*' -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"wronguser","password":"wrongpassword"}' 2>/dev/null)
status=$(echo "$response" | tail -n1)
if [ "$status" == "401" ] || [ "$status" == "429" ]; then
    echo -e "${GREEN}✓ PASS${NC}: Login with wrong credentials (HTTP $status)"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}: Login with wrong credentials (expected 401/429, got $status)"
    ((FAIL++))
fi

echo ""
echo "========================================"
echo -e "  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
else
    exit 0
fi
