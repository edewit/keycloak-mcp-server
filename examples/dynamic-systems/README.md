# Demo: systems registered at runtime, stored in PostgreSQL

The MCP server starts knowing no Keycloak at all. A control plane (here: `demo.sh` with `curl`) registers the system
`acme` through the admin API; the server stores it in PostgreSQL, generates its `private_key_jwt` key pair in the
database vault and answers with the JWKS URL. The demo then creates the generic `keycloak-mcp-server` client in
Keycloak's master realm pointing at that URL, creates the realm `acme-dev` with the public `mcp-consumer` client and
four users, and calls tools: as the service account, and as realm-local users whose own roles decide what they may do.
Two MCP containers share the database (`mcp` for the service account and the admin API, `mcp-users` for logins),
so the system registered once is known to both.

```
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql    # the PostgreSQL build of the server (see below)
docker compose up -d --build                                      # PostgreSQL :5490, Keycloak :8090 (admin/admin), MCP :8091 and :8092
./demo.sh                                                         # the four steps, idempotent
```

## The steps, by hand

**1. Register the system** (admin API; the bearer is the static `KC_MCP_ADMIN_TOKEN`, or an access token of a master
realm admin: `KC_MCP_ADMIN_ISSUER` names that realm, the default role is `realm:admin`, and `KC_MCP_ADMIN_AUDIENCE`
asks for `keycloak-mcp-server`, which the public client `keycloak-mcp-admin` of step 2b puts into its tokens; `admin-cli`
tokens are lightweight in Keycloak 26, without roles or audience, and are refused). The body has the fields of a systems file
entry; `signingKey` is `generate` (a new key pair in the database vault), `existing` (a key the vault already has,
provisioned by other means), or absent (existing if there is one, else generated). A `client_secret` system can name a
vault secret instead of carrying one: `"clientSecret": "vault:acme/client-secret"`.

```shell
curl -s -X PUT localhost:8091/admin/systems/acme \
  -H 'Authorization: Bearer demo-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "displayName": "ACME Corp.",
    "url": "http://keycloak:8080",
    "issuer": "http://localhost:8090/realms/master",
    "clientId": "keycloak-mcp-server",
    "clientAuth": "private_key_jwt",
    "defaultRealm": "acme-dev",
    "allowedRealms": ["acme-dev"],
    "version": "26.8.1",
    "signingKey": "generate"
  }' | jq .
```

With an access token instead of the static token (the public client `keycloak-mcp-admin` of step 2b):

```shell
TOKEN=$(curl -s http://localhost:8090/realms/master/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
curl -s localhost:8091/admin/systems \
  -H "Authorization: Bearer $TOKEN" | jq .
```

The answer carries no secrets, but `signingKey.kid`, `signingKey.jwksPath` (`/auth/keys/acme/jwks.json`),
`signingKey.jwksUrl` (as seen from the caller) and the entries (`/mcp/s/acme`, `/mcp/s/acme/acme-dev`). Inside the
compose network Keycloak reaches the MCP server as `http://mcp:8081`, so the JWKS URL for the client is
`http://mcp:8081/auth/keys/acme/jwks.json`. `GET /admin/systems` lists every system with its source repository
(`db-systems` here), `POST /admin/systems/acme/signing-key` rotates the key (the old one keeps its row, retired),
`DELETE /admin/systems/acme` removes it. `url` must be covered by `KC_MCP_ALLOWED_HOSTS`.

**2. The client in Keycloak's master realm**: `clients/keycloak-mcp-server.json` is a generic client representation
(confidential, service account, authenticator `client-jwt`, `use.jwks.url=true`) with the JWKS URL to fill in. The
demo creates it with `kcadm`, grants the service account master's `admin` role and puts that role into the client's
role scope (full scope allowed stays off), so one client administers every realm of this Keycloak. Keycloak fetches the public key the first time the MCP server asks for a token.

**3. The realm**: `realms/acme-dev.json` creates `acme-dev` with the public PKCE client `mcp-consumer` (audience
mapper `keycloak-mcp-server`, full scope off, the realm-management roles in its scope) and groups that carry
realm-management roles:

| user | password | group | realm-management roles | what the MCP server lets them do |
|---|---|---|---|---|
| `alice` | `alice-demo` | `/mcp-admins` | `realm-admin` | everything |
| `sam` | `sam-demo` | `/mcp-support` | `view-users`, `view-events`, `query-users`, `query-groups` | reads; writes come back `forbidden`, `search_tools` marks them `allowed: false` |
| `dave` | `dave-demo` | `/mcp-developers` | `manage-clients`, `view-clients`, `query-clients`, `view-realm`, `view-users` | client work; user changes are `forbidden` |
| `bob` | `bob-demo` | `/staff` | none (disabled) | the user the others act upon |

**4. Calls.** The service account server answers at the entry without a login:

```
./mcp-call.py http://localhost:8091/mcp/s/acme/acme-dev whoami
./mcp-call.py http://localhost:8091/mcp/s/acme/acme-dev keycloak_user_search '{"search": "alice"}'
```

The user server requires a login at the entry's realm and forwards the user's token, so Keycloak enforces their roles
and the audit record names the human:

```
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/s/acme/acme-dev whoami
./mcp-call.py --login sam:sam-demo     http://localhost:8092/mcp/s/acme/acme-dev keycloak_user_set_enabled '{"id": "bob", "enabled": true}'   # forbidden
./mcp-call.py --login dave:dave-demo   http://localhost:8092/mcp/s/acme/acme-dev keycloak_client_list '{}'
./mcp-call.py --login dave:dave-demo   http://localhost:8092/mcp/s/acme/acme-dev keycloak_user_delete '{"id": "bob", "username": "bob"}'      # forbidden
```

`mcp.json` and `mcp-oauth.json` configure an LLM client (LM Studio, Claude) for the two servers; the OAuth one logs
the user in at `acme-dev` with `mcp-consumer`.

## What the demo shows

- **Admin API + database storage**: `KC_MCP_STATIC_SYSTEMS=false`, `KC_MCP_DYNAMIC_SYSTEMS=true`, a datasource and
  `KC_MCP_ADMIN_ENABLED=true`; step 2b calls it with the Keycloak admin's own access token (client
  `keycloak-mcp-admin`) instead of the static one. Systems live in `kc_mcp_system`, keys in `kc_mcp_signing_key` (encrypted with
  `KC_MCP_STORAGE_SECRET_KEY`), audit rows in `kc_mcp_audit_event`; `psql -h localhost -p 5490 -U kcmcp kcmcp`.
- **Per-system JWKS**: no secret is shared or configured anywhere; Keycloak fetches the public key.
- **Two servers, one database**: `mcp-users` sees the system `mcp` registered, and both write audit rows. On
  `mcp-users` the `pii-audit-scrubber` pseudonymizes names in the console line only (`targets: console`), while the
  database keeps the full record.
- **Access restrictions by role**: the same tools, three users, three different outcomes.

```
docker compose down -v        # drops the databases and with them the registered system and its key
```
