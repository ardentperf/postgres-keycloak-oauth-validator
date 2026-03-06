#!/usr/bin/env bash
# Integration test runner for entra_validator
# Runs inside the test-client container.
# Environment variables:
#   PGHOST, PGPORT, PGDATABASE, PGPASSWORD (superuser for setup)
#   OAUTH_ISSUER   — mock server base issuer URL  e.g. https://entra-test-oauth:8443
#   (mock server cert must be trusted by the system CA store)
set -euo pipefail

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Build a client_id carrying test params via the /param/ mechanism.
# The mock server decodes the base64 JSON and uses the "claims" key to
# override the JWT claims, when "stage":"token" is set.
param_client_id() {
    printf '%s' "$1" | base64 -w0
}

# Try to connect using OAuth device flow.
# Pass client_id as base64(JSON) with claim overrides; psql uses /param/ issuer
# so the mock server decodes the params from client_id.
# Returns the combined stdout+stderr of psql (exit always 0 via ||true).
try_connect() {
    local user="$1"
    local client_id="$2"

    PGPASSWORD="" \
    psql \
        "host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$user \
         sslmode=require \
         oauth_issuer=$OAUTH_ISSUER/param \
         oauth_client_id=$client_id \
         oauth_scope=openid" \
        --no-password \
        -c "SELECT current_user;" \
        2>&1 || true
}

# The JWT iss claim and entra.expected_issuer are both set to the /param issuer
# so they match. psql fetches discovery from /param/.well-known/... and the
# config() returns issuer = https://HOST:PORT/param (matching oauth_issuer).
PARAM_ISSUER="$OAUTH_ISSUER/param"

echo "=== entra_validator integration tests ==="
echo "    Base issuer:  $OAUTH_ISSUER"
echo "    Param issuer: $PARAM_ISSUER"
echo ""

# ── Test 1: Valid user with correct role ──────────────────────────────────────
echo "Test 1: Valid user + correct role (db_user)"
# stage=token: mock server applies claims overrides at the token endpoint
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"$PARAM_ISSUER\",\"preferred_username\":\"testuser@example.com\",\"roles\":[\"db_user\"]}}")
OUT=$(try_connect testuser "$CLIENT")
if echo "$OUT" | grep -q "testuser"; then
    pass "Authenticated as testuser"
else
    fail "Expected successful connection as testuser"
    echo "    Output: $OUT"
fi

# ── Test 2: Valid user with wrong role ────────────────────────────────────────
echo "Test 2: Valid user + wrong role"
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"$PARAM_ISSUER\",\"preferred_username\":\"testuser@example.com\",\"roles\":[\"wrong_role\"]}}")
OUT=$(try_connect testuser "$CLIENT")
if echo "$OUT" | grep -qi "error\|denied\|fail\|fatal"; then
    pass "Connection rejected (wrong role)"
else
    fail "Expected connection to be rejected for wrong role"
    echo "    Output: $OUT"
fi

# ── Test 3: Multi-value required_values — any match ───────────────────────────
echo "Test 3: Multi-value required_values — db_admin matches"
# PG is configured with entra.required_values='db_user,db_admin', so db_admin alone is sufficient
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"$PARAM_ISSUER\",\"preferred_username\":\"testuser@example.com\",\"roles\":[\"db_admin\"]}}")
OUT=$(try_connect testuser "$CLIENT")
if echo "$OUT" | grep -q "testuser"; then
    pass "Authenticated with alternate role value (db_admin)"
else
    fail "Expected successful connection with db_admin role"
    echo "    Output: $OUT"
fi

# ── Test 4: Second user with valid role ───────────────────────────────────────
echo "Test 4: Second user (testuser2) with valid role"
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"$PARAM_ISSUER\",\"preferred_username\":\"testuser2@example.com\",\"roles\":[\"db_user\"]}}")
OUT=$(try_connect testuser2 "$CLIENT")
if echo "$OUT" | grep -q "testuser2"; then
    pass "Authenticated as testuser2"
else
    fail "Expected successful connection as testuser2"
    echo "    Output: $OUT"
fi

# ── Test 5: Wrong issuer in token ─────────────────────────────────────────────
echo "Test 5: Wrong issuer in token"
# Token carries iss=https://evil.example.com; entra_validator should reject it.
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"https://evil.example.com\",\"preferred_username\":\"testuser@example.com\",\"roles\":[\"db_user\"]}}")
OUT=$(try_connect testuser "$CLIENT")
if echo "$OUT" | grep -qi "error\|denied\|fail\|fatal"; then
    pass "Connection rejected (wrong issuer in token)"
else
    fail "Expected connection to be rejected for wrong issuer"
    echo "    Output: $OUT"
fi

# ── Test 6: Missing identity claim ───────────────────────────────────────────
echo "Test 6: Missing identity claim (preferred_username set to null = removed)"
# null values are stripped from the JWT by the mock server
CLIENT=$(param_client_id "{\"stage\":\"token\",\"claims\":{\"iss\":\"$PARAM_ISSUER\",\"sub\":\"only-sub\",\"preferred_username\":null,\"roles\":[\"db_user\"]}}")
OUT=$(try_connect testuser "$CLIENT")
if echo "$OUT" | grep -qi "error\|denied\|fail\|fatal"; then
    pass "Connection rejected (missing preferred_username)"
else
    fail "Expected connection to be rejected for missing identity claim"
    echo "    Output: $OUT"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
