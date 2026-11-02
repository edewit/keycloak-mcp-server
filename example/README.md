# Demo setup for keycloak-mcp-server

A ready-to-run Keycloak 26.8.1 with a `demo` realm shaped for the tool surface, plus Mailpit to catch the
action emails. Everything is throw-away (`docker compose down -v` resets it).

## Start

```shell
cd example
docker compose up -d
# Keycloak: http://localhost:8080  (admin console: admin / admin)
# Mailpit:  http://localhost:8025
```

Then run the MCP server on the host with one of the access levels in `env/`:

```shell
cd ..
set -a; source example/env/realm-admin.env; set +a
./mvnw quarkus:dev            # MCP endpoint: http://localhost:8081/mcp
```

Or let compose run it from the packaged jar (`./mvnw package` first):

```shell
KC_MCP_ENV_FILE=env/realm-manager.env docker compose --profile mcp up -d
```

Point your MCP client at `http://localhost:8081/mcp` (LM Studio: copy `mcp.json`).

## What is in the `demo` realm

| thing | details |
|---|---|
| users | `alice` (admins, team-a, `group-manager`, R&D), `bob` (devs/backend, `demo-app` app-user), `carol` (team-b, `support`), `dave` (disabled). Password = `<username>-demo`. |
| groups | `/admins` (→ editor), `/devs` (→ viewer) with `backend`, `frontend`, `/team-a` with `ops`, `/team-b` |
| realm roles | `viewer`, `editor` (composite of viewer), `group-manager`, `support` |
| clients | `demo-app` (confidential, PKCE, client roles `app-user`/`app-admin`), `mcp-consumer` (public PKCE, for later OIDC on the MCP endpoint) |
| MCP service accounts | `mcp-admin` → `realm-admin`; `mcp-manager` → view-users, manage-users, view-clients, view-events; `mcp-readonly` → view-* only. Secrets: `<clientId>-secret`. `mcp-jwt` → `realm-admin`, authenticates with `private_key_jwt` (JWKS URL → the MCP server) |
| identity provider | `corp-oidc` (disabled stub, hidden on login) |
| organization | `ACME Corp` (`acme`, domain acme.com) |
| realm settings | login + admin events on, organizations on, SMTP → Mailpit, password policy `length(8)`, unmanaged user attributes enabled (`department`) |
| second realm | `other` with user `zed`, deliberately outside `KC_MCP_ALLOWED_REALMS` |

## Access levels to demonstrate

| env file | what the model can do |
|---|---|
| `env/full-admin.env` | everything, every realm (admin user via admin-cli) |
| `env/realm-admin.env` | everything inside `demo` |
| `env/realm-manager.env` | user management only; client/realm/flow tools are hidden; `keycloak_user_delete` denied; group scope + no-escalation policies on |
| `env/read-only.env` | reads only, lazy exposure (just `search_tools` / `execute_tool`) |
| `env/multi-system.env` | two systems `prod` and `staging` (both this Keycloak) to show the `system` argument |
| `env/private-key-jwt.env` | client authentication with a signed JWT instead of a secret; see below |

## private_key_jwt demo

```shell
./example/gen-key.sh                                  # writes example/keys/mcp-jwt.pem (git-ignored)
set -a; source example/env/private-key-jwt.env; set +a
./mvnw quarkus:dev
curl http://localhost:8081/.well-known/jwks.json      # the public key Keycloak will fetch
```

The `mcp-jwt` client in the realm is configured with *Client Authenticator = Signed JWT* and
*JWKS URL = http://host.docker.internal:8081/.well-known/jwks.json*. On the first tool call the server signs a
client assertion with the private key, Keycloak fetches the JWKS from the running MCP server, validates the
assertion and issues the service-account token. The assertion's `kid` equals the JWK's `kid` (RFC 7638
thumbprint), so key rotation is a matter of swapping the PEM and restarting. Compose runs the same setup with
`KC_MCP_ENV_FILE=env/private-key-jwt.env docker compose --profile mcp up -d` (the key is mounted at `/keys`).

## Prompts to try

1. "Which users are in the demo realm?"
2. "Disable the user dave" / "Is dave enabled?" (dave starts disabled; enable him first)
3. "Add carol to the devs/backend group and tell me which roles she effectively has now."
4. "Send bob an email to reset his password" (then open Mailpit).
5. "Create a confidential client `billing-api` with redirect URI https://billing.example.com/* and PKCE."
6. "Show the client secret of demo-app" (masked) / "...reveal it".
7. "Which authentication flow is bound as browser flow? Copy it to `browser-mfa` and add a conditional OTP sub-flow."
8. "List failed logins of the last day."
9. "Turn on self-registration in the demo realm." (destructive → confirmation)
10. "Link the identity provider corp-oidc to the ACME organization."
11. With `realm-manager.env`: "Delete user dave" (denied), "Create a client" (tool not visible),
    "Give carol the admin role" (escalation refused).
12. With `other` realm: "List users in realm other" (realm_not_allowed).

## Reset

```shell
docker compose down -v
```
