#!/usr/bin/env bash
# Integration test orchestrator for entra_validator.
# Runs entirely in Docker (no Kubernetes required).
# Usage: ./test/run_integration_test.sh [--keep]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEEP_CONTAINERS="${1:-}"

NETWORK="entra-test-net"
PG_CONTAINER="entra-test-pg"
OAUTH_CONTAINER="entra-test-oauth"
CLIENT_CONTAINER="entra-test-client"
CERT_DIR="$SCRIPT_DIR/certs"
LOG_DIR="$SCRIPT_DIR/logs"
SO_DIR="$SCRIPT_DIR/so"

PGPORT=5432
PGUSER=postgres
PGDATABASE=postgres

cleanup() {
    if [[ "$KEEP_CONTAINERS" != "--keep" ]]; then
        echo "Cleaning up..."
        docker rm -f "$PG_CONTAINER" "$OAUTH_CONTAINER" "$CLIENT_CONTAINER" 2>/dev/null || true
        docker network rm "$NETWORK" 2>/dev/null || true
    else
        echo "Keeping containers (--keep specified)"
    fi
}
trap cleanup EXIT

# ── Step 0: Prepare directories ───────────────────────────────────────────────
mkdir -p "$CERT_DIR" "$LOG_DIR" "$SO_DIR"

# ── Step 1: Generate self-signed TLS cert for mock OAuth server ───────────────
echo "==> Generating TLS certificates..."
if [[ ! -f "$CERT_DIR/server.crt" ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$CERT_DIR/server.key" \
        -out    "$CERT_DIR/server.crt" \
        -subj   "/CN=127.0.0.1" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    echo "    Generated $CERT_DIR/server.crt"
fi

# ── Step 2: Build validator .so ───────────────────────────────────────────────
echo "==> Building entra_validator.so..."
docker build \
    --target builder \
    -t entra-validator-builder \
    -f "$REPO_DIR/docker/Dockerfile" \
    "$REPO_DIR" \
    --quiet

# Extract the .so from the builder image
docker create --name entra-so-extractor entra-validator-builder /bin/true 2>/dev/null
docker cp entra-so-extractor:/srv/build/entra_validator.so "$SO_DIR/entra_validator.so"
docker rm -f entra-so-extractor 2>/dev/null

echo "    Built: $SO_DIR/entra_validator.so"

# ── Step 3: Build test images ─────────────────────────────────────────────────
echo "==> Building test images..."
docker build -t entra-mock-oauth -f "$SCRIPT_DIR/Dockerfile.mock-server" "$SCRIPT_DIR" --quiet
docker build -t entra-test-client -f "$SCRIPT_DIR/Dockerfile.test-client" "$SCRIPT_DIR" --quiet

# ── Step 4: Create Docker network ─────────────────────────────────────────────
docker network rm "$NETWORK" 2>/dev/null || true
docker network create "$NETWORK" --driver bridge

# ── Step 5: Start mock OAuth server ──────────────────────────────────────────
echo "==> Starting mock OAuth server..."
docker run -d --name "$OAUTH_CONTAINER" \
    --network "$NETWORK" \
    -v "$CERT_DIR:/certs:ro" \
    -e MOCK_OAUTH_CERT=/certs/server.crt \
    -e MOCK_OAUTH_KEY=/certs/server.key \
    -p 18443:8443 \
    entra-mock-oauth 8443

# Wait for OAuth server to be ready
for i in $(seq 1 20); do
    if docker exec "$OAUTH_CONTAINER" python3 -c "import http.client, ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; c=http.client.HTTPSConnection('127.0.0.1',8443,context=ctx); c.request('GET','/healthz'); r=c.getresponse(); exit(0 if r.status==200 else 1)" 2>/dev/null; then
        break
    fi
    sleep 1
    if [[ $i -eq 20 ]]; then
        echo "ERROR: mock OAuth server did not start"; exit 1
    fi
done
echo "    Mock OAuth server ready"
OAUTH_PORT=8443
OAUTH_ISSUER="https://127.0.0.1:${OAUTH_PORT}"

# ── Step 6: Start PostgreSQL ──────────────────────────────────────────────────
echo "==> Starting PostgreSQL..."

# postgresql.conf additions
PG_CONF=$(cat <<EOF
oauth_validator_libraries = 'entra_validator'
entra.expected_issuer = '${OAUTH_ISSUER}'
entra.identity_claim = 'preferred_username'
entra.required_claim = 'roles'
entra.required_values = 'db_user,db_admin'
entra.debug = on
log_min_messages = debug1
ssl = on
ssl_cert_file = '/etc/ssl/pg/server.crt'
ssl_key_file  = '/etc/ssl/pg/server.key'
EOF
)

# pg_hba.conf
PG_HBA=$(cat <<EOF
local all all trust
hostssl all all 127.0.0.1/32 oauth issuer="${OAUTH_ISSUER}" scope="openid" validator="entra_validator"
hostssl all all ::1/128 oauth issuer="${OAUTH_ISSUER}" scope="openid" validator="entra_validator"
hostssl all all 0.0.0.0/0 oauth issuer="${OAUTH_ISSUER}" scope="openid" validator="entra_validator"
host all all 0.0.0.0/0 trust
EOF
)

# pg_ident.conf: map preferred_username to PG roles
# testuser@example.com -> testuser
# testuser2@example.com -> testuser2
PG_IDENT=$(cat <<EOF
entra testuser@example.com testuser
entra testuser2@example.com testuser2
EOF
)

docker run -d --name "$PG_CONTAINER" \
    --network "$NETWORK" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_PASSWORD=postgres \
    -v "$SO_DIR/entra_validator.so:/usr/lib/postgresql/18/lib/entra_validator.so:ro" \
    -v "$CERT_DIR/server.crt:/etc/ssl/pg/server.crt:ro" \
    -v "$CERT_DIR/server.key:/etc/ssl/pg/server.key:ro" \
    -p 15432:5432 \
    ghcr.io/cloudnative-pg/postgresql:18-standard-trixie \
    postgres -c "config_file=/etc/postgresql/postgresql.conf"

# Wait for PG to be ready
for i in $(seq 1 30); do
    if docker exec "$PG_CONTAINER" pg_isready -U postgres 2>/dev/null; then
        break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo "ERROR: PostgreSQL did not start"
        docker logs "$PG_CONTAINER"
        exit 1
    fi
done

# Configure PG
echo "$PG_CONF" | docker exec -i "$PG_CONTAINER" bash -c "cat >> /var/lib/postgresql/data/postgresql.conf"
echo "$PG_HBA"  | docker exec -i "$PG_CONTAINER" bash -c "cat > /var/lib/postgresql/data/pg_hba.conf"
echo "$PG_IDENT"| docker exec -i "$PG_CONTAINER" bash -c "cat > /var/lib/postgresql/data/pg_ident.conf"

# Fix key file permissions
docker exec "$PG_CONTAINER" bash -c "cp /etc/ssl/pg/server.key /var/lib/postgresql/server.key && chmod 600 /var/lib/postgresql/server.key"

# Create roles
docker exec -i "$PG_CONTAINER" psql -U postgres <<'SQL'
CREATE USER testuser LOGIN;
CREATE USER testuser2 LOGIN;
SQL

# Reload config
docker exec "$PG_CONTAINER" psql -U postgres -c "SELECT pg_reload_conf();"
echo "    PostgreSQL ready"

# Get OAuth server IP within Docker network
OAUTH_IP=$(docker inspect "$OAUTH_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "    OAuth server IP: $OAUTH_IP"

# ── Step 7: Run tests ─────────────────────────────────────────────────────────
echo "==> Running integration tests..."
PG_IP=$(docker inspect "$PG_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

docker run --rm --name "$CLIENT_CONTAINER" \
    --network "$NETWORK" \
    -v "$CERT_DIR/server.crt:/certs/oauth-ca.crt:ro" \
    -e PGHOST="$PG_IP" \
    -e PGPORT="$PGPORT" \
    -e PGDATABASE="$PGDATABASE" \
    -e PGUSER="$PGUSER" \
    -e PGPASSWORD="postgres" \
    -e OAUTH_ISSUER="https://${OAUTH_IP}:${OAUTH_PORT}" \
    -e OAUTH_CA_FILE="/certs/oauth-ca.crt" \
    -e OAUTH_PARAM_PATH="/param" \
    entra-test-client 2>&1 | tee "$LOG_DIR/test-output.log"

echo ""
echo "==> Test complete. Logs in $LOG_DIR/"
