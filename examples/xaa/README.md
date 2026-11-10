# Cross-App Access: the enterprise IdP decides who connects, Keycloak decides what they may do

[keycloak-mcp-server](../../README.md) › [examples](../README.md)

Cross-App Access (XAA, [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)),
in MCP [Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization):
the MCP client trades the user's SSO identity for an **ID-JAG** at the enterprise IdP and redeems it at the MCP
server's authorization server. No login page of that server, no consent screen; the IdP admin decides which apps an
agent may connect for whom. [oauth.net/cross-app-access](https://oauth.net/cross-app-access/) lists implementations.

```
MCP client (agent)
  │ 1. POST /mcp → 401 resource_metadata → PRM: resource http://localhost:8103, AS http://localhost:8101/realms/acme
  │ 2. SSO at the enterprise IdP → ID token                               (once; a browser flow in a real IdP)
  │ 3. token exchange at the IdP (RFC 8693)                                 ◀── IdP policy: may alice connect agent
  │      subject_token = ID token, requested_token_type = …:id-jag,              to http://localhost:8103?
  │      audience = http://localhost:8101/realms/acme, resource = http://localhost:8103
  │    → ID-JAG: typ oauth-id-jag+jwt, iss IdP, sub e-1001, aud realm acme, client_id agent, resource, 5 min
  │ 4. JWT authorization grant at Keycloak (RFC 7523): grant_type = …:jwt-bearer, assertion = ID-JAG
  │    → access token of the Keycloak user linked to e-1001, aud ∋ http://localhost:8103, kc-admin-api
  ▼
MCP server (KC_MCP_DELEGATION=forward) → Admin API with alice's token → her realm-management roles apply
```

The MCP server itself needs nothing new: it is a resource server checking `aud`, as in `run-modes/user-forward`.
Everything happens between client, IdP and Keycloak.

## Start

```shell
cd examples/xaa
docker compose up -d --wait   # Keycloak 26.8.2 on http://localhost:8101 (admin / admin), enterprise IdP on :8102
```

Then the MCP server on the host:

```shell
cd ../..
set -a; source examples/xaa/env/xaa.env; set +a
./mvnw quarkus:dev -pl modules/backend -am     # MCP endpoint: http://localhost:8103/mcp
```

or packaged, inside compose (`./mvnw package -DskipTests` first): `docker compose --profile mcp up -d --build`.
IntelliJ: `.run/` has `quarkus:dev (xaa: …)`, stack up, demo, down. `docker compose down -v` resets the realm.

## Try it

```shell
./demo.sh                                                    # all cases below; SHOW_TOKENS=1 prints the three tokens
./xaa-call.py --login alice:alice-demo whoami                # progress on stderr, tool result on stdout
./xaa-call.py --login carol:carol-demo keycloak_user_search '{"search": "*"}'
./xaa-call.py --login alice:alice-demo --show-tokens         # ID token, ID-JAG, access token; no tool call 
```

| user | IdP group | Keycloak | result |
|---|---|---|---|
| `alice` | `keycloak-operators` | `/keycloak-admins` → `realm-admin` | everything works |
| `carol` | `keycloak-operators` | `/keycloak-support` → `view-users`, `view-events` | reads work, writes `forbidden` |
| `bob` | `sales` | `/keycloak-admins` → `realm-admin` | the **IdP** refuses the ID-JAG: `access_denied` |
| `dave` | `keycloak-operators` | no account | **Keycloak** refuses the ID-JAG: `User not found` |

Passwords `<username>-demo`. `bob` shows the point of XAA: Keycloak would let him in, the company's IdP says no.
Edit `idp/policy.json` (re-read on every request) to move users between groups or drop the app.

## What is in the stack

| thing | details |
|---|---|
| Keycloak | 26.8.2 with `--features=identity-assertion-jwt` (experimental, draft revision 01, accepting side only). Realm `acme`: events `JWT_AUTHORIZATION_GRANT`, `JWT_AUTHORIZATION_GRANT_ERROR` (with `identity_provider_user_id`), admin events |
| identity provider `enterprise` | `keycloak-oidc`, issuer `http://localhost:8102`, JWKS `http://idp:8102/jwks`; `jwtAuthorizationGrantEnabled`, no assertion reuse, max assertion lifetime 300 s; `linkOnly`, hidden on the login page |
| client `agent` | the MCP client's registration at the authorization server: confidential (`agent-at-acme`), no browser flow, no service account; `oauth2.jwt.authorization.grant.enabled`, `…grant.idp=enterprise`. Default scope `kc-admin-api` (Admin API audience, 26.8.2); audience mapper `http://localhost:8103` |
| users | `alice`, `carol`, `bob` linked to the IdP subjects `e-1001`, `e-1003`, `e-1002` (`federatedIdentities` in the realm file); `erin`, `frank` (disabled) to look at |
| `idp/idp.py` | stand-in enterprise IdP, Python standard library only: password sign-in → ID token, token exchange → ID-JAG under `policy.json`, JWKS. Keycloak cannot issue ID-JAGs yet ([keycloak#48818](https://github.com/keycloak/keycloak/issues/48818)) |
| `idp/policy.json` | clients (`agent` / `agent-at-idp`), users with `sub` and groups, apps: `audience` (AS issuer), `resource` (MCP server), `clients` (IdP client id → `client_id` at the AS), allowed `groups`, `scopes` |
| MCP server | `env/xaa.env`: `KC_MCP_DELEGATION=forward`, `QUARKUS_OIDC_TENANT_ENABLED=true`, `QUARKUS_OIDC_TOKEN_AUDIENCE=http://localhost:8103`; no admin credentials |

## Keycloak 26.8.2 as the ID-JAG receiver: verified behavior

| ID-JAG property | Keycloak |
|---|---|
| signature (IdP JWKS), `iss` | checked |
| `aud` | checked: realm issuer (the token endpoint URL is accepted too) |
| `client_id` | must equal the authenticated client |
| `jti`, `iat` | required; a second use answers `Token reuse detected` |
| `sub` | must be linked to a user (`federated-identity`); no just-in-time creation |
| `typ: oauth-id-jag+jwt` | **not checked**, a plain `JWT` passes |
| `resource` | **ignored**: the access token's `aud` comes from the client's mappers, hence the audience mapper on `agent` |
| `scope` | **ignored**: the request's `scope` and the client's default scopes decide |
| `exp` | an assertion valid for 1 h passed despite the 300 s maximum |
| access token | 300 s here (the realm's access token lifespan, the assertion's 5 minutes), no refresh token: the client gets a new ID-JAG when it expires |

Consequences:

- **One client per MCP server at Keycloak.** The audience comes from `agent`'s mapper, not from the ID-JAG: every
  ID-JAG for `agent` yields a token for `http://localhost:8103`. Separate servers need separate clients.
- **The IdP's scope narrowing does not reach the token.** The roles are the Keycloak user's; narrow with the client's
  role scope (*Full scope allowed* off), as `delegated-auth` does for its actor.
- **Account linking is up to the operator.** A user without a link to the IdP subject cannot use XAA (`dave`).

## MCP clients

- **Discovery gap.** Keycloak advertises `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported`,
  but not `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]`, which
  Enterprise-Managed Authorization uses to detect support. `xaa-call.py` reports it in step 1 and goes on.
- **Client configuration.** Clients with XAA support (Claude, VS Code preview, Codex CLI, see oauth.net) are set up by
  the organization: IdP endpoints, client credentials at the IdP and at the authorization server. This example's IdP
  is a stand-in, so they cannot use it; with Okta, Ping and others as the IdP, register its issuer as the
  `enterprise` identity provider and keep the rest.
