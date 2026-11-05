# Demo: tenants as systems, one MCP entry per tenant or realm

Two tenants on one Keycloak. Tenant A owns the realms `realm-a-1` (employees) and `realm-a-2` (customers),
tenant B owns `realm-b-1`. An onboarding job (`init/onboard-tenants.sh`, what a SaaS control plane would run)
gives each tenant a confidential client `keycloak-mcp-server-<tenant>` in the master realm, authenticating with
*Signed JWT* and the JWKS URL `http://mcp:8081/auth/keys/<tenant>/jwks.json`, and grants its service account
the admin roles of the tenant's realms (master's `<realm>-realm` client roles). The MCP server learns the tenants from `systems.json`, generates a key pair
per tenant on first use, and Keycloak fetches the public key from the MCP server when the first token is
requested. No secret is configured anywhere.

In a real SaaS each tenant is its own Keycloak and the client is simply `keycloak-mcp-server` in that server's
master realm; here the two share one Keycloak, hence the tenant suffix.

```
docker compose up --build          # Keycloak on :8090 (admin/admin), MCP server on :8091
```

Then, from this directory:

```
curl -s localhost:8091/auth/keys/tenant-a/jwks.json | jq .          # the key Keycloak fetches for tenant A
./mcp-call.py http://localhost:8091/mcp/s/tenant-a whoami            # entry bound to tenant A, realm-a-1 by default
./mcp-call.py http://localhost:8091/mcp/s/tenant-a keycloak_user_search '{"search": "alice"}'
./mcp-call.py http://localhost:8091/mcp/s/tenant-a keycloak_user_search '{"realm": "realm-a-2", "search": "anna"}'
./mcp-call.py http://localhost:8091/mcp/s/tenant-a/realm-a-2 keycloak_user_search '{"search": "anna"}'
./mcp-call.py http://localhost:8091/mcp/s/tenant-a/realm-a-2 keycloak_user_search '{"realm": "realm-a-1"}'
                                                                     # -> entry_mismatch: bound to realm-a-2
./mcp-call.py http://localhost:8091/mcp/s/tenant-b/realm-b-1 keycloak_user_search '{"search": "carol"}'
./mcp-call.py http://localhost:8091/mcp/s/tenant-b keycloak_user_search '{"realm": "realm-a-1"}'
                                                                     # -> realm_not_allowed: not tenant B's realm
./mcp-call.py http://localhost:8091/mcp keycloak_user_search '{"system": "tenant-a", "realm": "realm-a-1", "search": "bob"}'
                                                                     # the root takes an explicit system
```

`mcp.json` configures an LLM client (LM Studio, Claude) with one logical MCP server per tenant or realm.

What the demo shows:

- **`KC_MCP_STATIC_SYSTEMS=false` + `KC_MCP_DYNAMIC_SYSTEMS=true` + `KC_MCP_SYSTEMS_FILE`**: systems come from
  the mounted `systems.json` only, re-read when it changes. Add a tenant to the file (and run the onboarding
  for it) and its entry works on the next call, without a restart.
- **Per-tenant keys**: `KC_MCP_KEYS_DIR` on a volume; `docker compose logs mcp` shows
  `[tenant-a] generated a private_key_jwt key` on the first run and reuses the key afterwards. A tenant only
  ever registers a public key.
- **`version` in `systems.json`**: the user-login server never uses its own credentials, so it cannot read the
  server info; the configured version keeps the version checks on (`whoami` shows `server.version`). Edit the
  file while the stack runs: it is re-read on the next call.
- **`issuer` in `systems.json`**: the MCP server reaches Keycloak at the internal `http://keycloak:8080`, but
  Keycloak's issuer is its public hostname `http://localhost:8090/realms/master`, and that is the audience a
  client assertion must carry. Without it Keycloak answers "Invalid token audience".
- **Entries**: `/mcp/s/tenant-a` pins the system, `/mcp/s/tenant-a/realm-a-2` pins system and realm; a
  disagreeing `system` or `realm` argument is refused with `entry_mismatch`, a realm the tenant does not own with
  `realm_not_allowed`.
- **`KC_MCP_ALLOWED_HOSTS=keycloak:8080`**: a system in `systems.json` pointing elsewhere is refused and logged.

## User login per realm (`mcp-users`, port 8092)

The second server holds no admin credentials: its MCP endpoint requires an OAuth login and forwards the user's
own token to the Admin API (`KC_MCP_DELEGATION=forward`, `QUARKUS_OIDC_TENANT_ENABLED=true`). A realm entry logs
its users in at that realm: `/mcp/s/tenant-a/realm-a-1` verifies tokens of `realm-a-1`, `/mcp/s/tenant-b/realm-b-1`
those of `realm-b-1`; the root `/mcp` uses the master realm. Each realm has the public PKCE client `mcp-consumer`
whose tokens carry `aud=keycloak-mcp-server` (full scope off, the realm-management roles are in its role scope).
Keycloak enforces the user's roles, and the audit line names the human.

| user | realm | roles via group | what happens |
|---|---|---|---|
| `alice / alice-demo` | `realm-a-1` | `/mcp-admins` → `realm-admin` | everything works |
| `sam / sam-demo` | `realm-a-1` | `/mcp-support` → `view-users`, `view-events` | reads work, writes come back `forbidden`, `search_tools` marks them `allowed: false` |
| `bob / bob-demo` | `realm-a-1` | none (and disabled) | cannot log in |
| `anna / anna-demo` | `realm-a-2` | `/mcp-admins` | tenant A's customer realm |
| `carol / carol-demo` | `realm-b-1` | `/mcp-admins` | tenant B |

```
./mcp-call.py http://localhost:8092/mcp/s/tenant-a/realm-a-1 whoami          # 401 + WWW-Authenticate … resource_metadata
curl -s localhost:8092/.well-known/oauth-protected-resource/mcp/s/tenant-a/realm-a-1 | jq .   # names realm-a-1
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/s/tenant-a/realm-a-1 whoami
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/s/tenant-a/realm-a-1 keycloak_user_search '{"search": "sam"}'
./mcp-call.py --login sam:sam-demo http://localhost:8092/mcp/s/tenant-a/realm-a-1 keycloak_user_set_enabled '{"id": "bob", "enabled": true}'
                                                                               # -> forbidden: sam lacks manage-users
./mcp-call.py --login carol:carol-demo http://localhost:8092/mcp/s/tenant-b/realm-b-1 keycloak_user_search '{"search": "dave"}'
./mcp-call.py --login alice:alice-demo@realm-a-1 http://localhost:8092/mcp/s/tenant-b/realm-b-1 whoami
                                                                               # -> 401: a realm-a-1 token is no good for tenant B
```

`mcp-oauth.json` configures LM Studio with the three realm entries and `"auth": {"CLIENT_ID": "mcp-consumer"}`;
LM Studio opens the browser at the right realm for each entry. To switch users, remove the server in LM Studio and
add it again, or log out in the Keycloak account console.

```
docker compose down -v             # also drops the generated keys and the onboarded clients
```
