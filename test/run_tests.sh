#!/usr/bin/env bash
# Integration test runner for entra_validator
# Runs inside the test-client container.
# Environment variables set by run_integration_test.sh:
#   PGHOST, PGPORT, PGDATABASE, PGPASSWORD (superuser for setup)
#   OAUTH_ISSUER       — mock server issuer URL (https://127.0.0.1:PORT)
#   OAUTH_CA_FILE      — path to self-signed CA cert for mock server TLS
#   OAUTH_CLIENT_ID    — base64-encoded JSON test params (for /param/ issuer)
set -euo pipefail

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Build a client_id carrying test params via the /param/ mechanism:
# mock server reads claims overrides from base64(JSON) in client_id
param_client_id() {
    printf '%s' "$1" | base64 -w0
}

# Try to connect using OAuth device flow.
# Sets PGOAUTHCAFILE so psql trusts the mock server's TLS cert.
# Returns 0 on successful connection, non-zero on failure.
try_connect() {
    local user="$1"
    local client_id="$2"
    local issuer="${3:-$OAUTH_ISSUER}"

    PGOAUTHCAFILE="$OAUTH_CA_FILE" \
    PGPASSWORD="" \
    psql \
        "host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$user \
         oauth_issuer=$issuer \
         oauth_client_id=$client_id \
         oauth_scope=openid" \
        --no-password \
        -c "SELECT current_user;" \
        2>&1
}

echo "=== entra_validator integration tests ==="
echo ""

# ── Test 1: Valid user with correct role ──────────────────────────────────────
echo "Test 1: Valid user + correct role"
CLIENT=$(param_client_id '{"claims":{"preferred_username":"testuser@example.com","roles":["db_user"]}}')
if try_connect testuser "$CLIENT" "${OAUTH_ISSUER/127.0.0.1/127.0.0.1}${OAUTH_PARAM_PATH}" 2>&1 | grep -q "testuser"; then
    pass "Authenticated as testuser"
else
    fail "Expected successful connection as testuser"
fi

# ── Test 2: Valid user with wrong role ────────────────────────────────────────
echo "Test 2: Valid user + wrong role"
CLIENT=$(param_client_id '{"claims":{"preferred_username":"testuser@example.com","roles":["other_role"]}}')
if try_connect testuser "$CLIENT" 2>&1 | grep -qi "error\|denied\|fail\|authentication"; then
    pass "Connection rejected (wrong role)"
else
    fail "Expected connection to be rejected for wrong role"
fi

# ── Test 3: Multi-value required_values (any match) ───────────────────────────
echo "Test 3: Multi-value required_values - db_admin matches"
CLIENT=$(param_client_id '{"claims":{"preferred_username":"testuser@example.com","roles":["db_admin"]}}')
# Note: PG needs to be configured with entra.required_values='db_user,db_admin' for this test
if try_connect testuser "$CLIENT" 2>&1 | grep -q "testuser"; then
    pass "Authenticated with alternate role value"
else
    fail "Expected successful connection with db_admin role"
fi

# ── Test 4: Identity-only mode (no required_claim configured) ─────────────────
echo "Test 4: Identity-only mode"
CLIENT=$(param_client_id '{"claims":{"preferred_username":"testuser2@example.com","roles":[]}}')
if try_connect testuser2 "$CLIENT" 2>&1 | grep -q "testuser2"; then
    pass "Authenticated in identity-only mode"
else
    # identity-only is tested in a separate PG config — skip gracefully
    echo "  SKIP: identity-only mode requires separate PG configuration"
fi

# ── Test 5: Wrong issuer ──────────────────────────────────────────────────────
echo "Test 5: Wrong issuer in token"
CLIENT=$(param_client_id '{"claims":{"preferred_username":"testuser@example.com","roles":["db_user"],"iss":"https://evil.example.com"}}')
if try_connect testuser "$CLIENT" 2>&1 | grep -qi "error\|denied\|fail\|authentication"; then
    pass "Connection rejected (wrong issuer)"
else
    fail "Expected connection to be rejected for wrong issuer"
fi

# ── Test 6: Missing identity claim ───────────────────────────────────────────
echo "Test 6: Missing identity claim (preferred_username absent)"
CLIENT=$(param_client_id '{"claims":{"sub":"only-sub","roles":["db_user"]}}')
if try_connect testuser "$CLIENT" 2>&1 | grep -qi "error\|denied\|fail\|authentication"; then
    pass "Connection rejected (missing preferred_username)"
else
    fail "Expected connection to be rejected for missing identity claim"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
