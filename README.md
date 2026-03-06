[![CloudNativePG](./logo/cloudnativepg.png)](https://cloudnative-pg.io/)

# PostgreSQL OAuth Validator for Microsoft Entra ID

**EXPERIMENTAL** | Requires PostgreSQL 18+

This module enables PostgreSQL 18 to validate OAuth tokens issued by
Microsoft Entra ID (Azure AD). It performs **offline JWT claim-based
validation** — no HTTP calls to an external authorization server are needed.

On each connection:
1. The JWT `iss` claim is verified against `entra.expected_issuer` (if configured)
2. The configured identity claim (default: `preferred_username`) is extracted
   and used as the PostgreSQL `authn_id` for identity mapping
3. Optionally, a roles/groups array claim is checked for required membership

The module is designed for use with [CloudNativePG](https://cloudnative-pg.io/)
and works with any OIDC provider that issues v2-style JWT access tokens
(Entra ID, Auth0, Okta, etc.).

---

## Features

- **Offline JWT validation** — no network calls per connection
- **Configurable identity claim** — use `preferred_username`, `email`, `oid`, `sub`, etc.
- **Flexible authorization** — optional check for required roles/groups
- **Multi-value authorization** — `entra.required_values` accepts a comma-separated
  list; any matching value grants access
- **Identity-only mode** — skip authorization checks entirely (just map identity)
- **Configurable via PostgreSQL GUC parameters**

---

## Quick Start: CloudNativePG

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: pg-oauth
spec:
  imageName: ghcr.io/cloudnative-pg/postgresql:18-minimal-trixie
  instances: 1

  postgresql:
    extensions:
      - name: entra-validator
        ld_library_path:
          - system
        image:
          reference: ghcr.io/ardentperf/postgres-entra-oauth-validator:18-dev-trixie
    parameters:
      oauth_validator_libraries: "entra_validator"
      entra.expected_issuer: "https://login.microsoftonline.com/TENANT_ID/v2.0"
      entra.identity_claim: "preferred_username"
      entra.required_claim: "roles"
      entra.required_values: "db_user,db_admin"
      entra.debug: "on"
    pg_hba:
      - hostssl all all 0.0.0.0/0 oauth issuer="https://login.microsoftonline.com/TENANT_ID/v2.0" scope="api://APP_ID/pg_access" validator="entra_validator"
```

For a complete example, see [`examples/cnpg/cluster.yaml`](examples/cnpg/cluster.yaml).

---

## GUC Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entra.expected_issuer` | string | NULL | Expected JWT `iss` claim. If set, tokens with a different issuer are rejected. Example: `https://login.microsoftonline.com/TENANT_ID/v2.0` |
| `entra.identity_claim` | string | `preferred_username` | JWT claim to use as `authn_id`. Use with `pg_ident` to map to PG roles. |
| `entra.required_claim` | string | NULL | JWT array claim to check for authorization (e.g., `roles`, `groups`). If NULL, authorization is always granted. |
| `entra.required_values` | string | NULL | Comma-separated list of allowed values. Authorization succeeds if the `required_claim` array contains **any** of these values. E.g., `db_user,db_admin` |
| `entra.debug` | bool | `off` | Enable verbose debug logging. Does not log token content. |

All GUCs are reloadable via `SIGHUP` / `SELECT pg_reload_conf()`.

---

## Entra ID Setup

### App Registration

1. Go to [portal.azure.com](https://portal.azure.com) → **Entra ID** → **App registrations** → **New registration**
2. Name: `pg-oauth-lab`, Supported account types: single tenant
3. Click **Register**
4. Note the **Application (client) ID** and **Directory (tenant) ID**

### Enable Device Flow

1. In your app registration → **Authentication**
2. Under **Advanced settings** → **Allow public client flows** → **Yes**
3. Click **Save**

### Expose an API

1. **Expose an API** → **Add a scope**
2. Set Application ID URI (accept the default or set `api://APP_ID`)
3. Scope name: `pg_access`, Admin consent: **Yes**, click **Add scope**

### Add App Roles (for role-based access)

1. **App roles** → **Create app role**
2. Display name: `Database User`, Value: `db_user`, Allowed member types: Users/Groups
3. Repeat for any additional roles
4. Go to **Enterprise Applications** → find your app → **Users and groups** → assign your user to the `db_user` role

### Set Token Version

1. **Manifest** → set `"accessTokenAcceptedVersion": 2` → **Save**

---

## psql Device Flow

```bash
psql "host=<your-pg-host> \
    user=<your-pg-username> \
    dbname=<dbname> \
    oauth_issuer=https://login.microsoftonline.com/TENANT_ID/v2.0 \
    oauth_client_id=APP_ID \
    oauth_scope='api://APP_ID/pg_access'"
```

psql will display a device code URL. Open it in a browser, sign in with your
Entra account, then psql will automatically obtain the token and connect.

Your PostgreSQL username must match the value of the configured `identity_claim`
(default: `preferred_username`, i.e., your Entra UPN like `user@domain.com`)
unless a `pg_ident` map is used to translate it.

---

## Build Instructions

### Local

```bash
meson setup build
meson compile -C build
```

The compiled `entra_validator.so` will be in the `build/` directory.

### Docker

```bash
docker build -t entra-validator -f docker/Dockerfile .
```

---

## Security Notes

- No cryptographic JWT signature verification is performed. The token is trusted
  based on the transport-layer security of the PostgreSQL connection (TLS) and
  the issuer claim check. For production use, ensure `ssl = on` and restrict
  pg_hba to `hostssl`.
- Set `entra.debug = off` in production to minimize log verbosity.
- The `preferred_username` claim can be spoofed if the access token is obtained
  by a malicious client; always ensure tokens are issued by the expected issuer.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).
