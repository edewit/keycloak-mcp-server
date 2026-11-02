# keycloak-mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server for administering Keycloak, built with Quarkus
and `quarkus-mcp-server` (streamable HTTP). Functionally modelled on
[mcp-keycloak-admin](https://github.com/edewit/mcp-keycloak-admin) (72 `keycloak_*` tools), but designed for
**small local models**: the model-facing surface is kept tiny through lazy tool loading.

Status: phases 1–4 of `sketch/notes/implementation-plan.md` are implemented: all 72 reference tools (users,
sessions, groups, roles, clients, client scopes, identity providers, organizations, user federation, authentication
flows, events, realm) plus search, exposure modes, guardrails and the extension SPI. See §Roadmap for what is left.

## How the model sees it

`tools/list` depends on `kc-mcp.tool-exposure`:

| mode          | `tools/list` contains                                   |
|---------------|---------------------------------------------------------|
| `hybrid`      | `search_tools`, `execute_tool` + the hot tools (default) |
| `lazy`        | `search_tools`, `execute_tool` only                      |
| `direct`      | every tool, like the reference implementation            |
| `progressive` | hybrid + whatever the last `search_tools` surfaced, per connection (needs clients that honour `tools/list_changed`) |

* `search_tools(query, category?, limit?)` – lexical search over names, titles, descriptions, parameters and a
  hand-maintained synonym table ("kick" → logout, "ldap" → federation, …). Returns name, description and the
  input schema, so the model can call `execute_tool` in the next turn. Without arguments it lists the categories.
* `execute_tool(name, arguments, confirm?)` – dispatches through the same invoker as direct calls:
  policy → argument validation/coercion → realm check → confirmation → handler → audit log.
  Errors are structured (`unknown_tool` with `didYouMean`, `invalid_arguments` with `problems` + schema,
  `realm_not_allowed`, `confirmation_required`, `read_only_mode`, `not_found`, `conflict`, `keycloak_unreachable`, …)
  and always flagged `isError: true`.
* Hidden tools stay callable by name, so a model that guesses `keycloak_user_search` in lazy mode still succeeds.
* Identifiers are forgiving: users by id or username, clients by id or clientId, groups by id, path or name.
  Booleans/integers given as strings are coerced; `max` is clamped to `kc-mcp.result-max-items`.

## Guardrails

* `KC_MCP_READ_ONLY=true` hides and refuses every WRITE/DESTRUCTIVE tool.
* `KC_MCP_ALLOWED_REALMS=a,b` restricts every call to those realms; a startup check verifies the credentials reach
  them (`kc-mcp.startup-check=warn|fail|off`).
* `KC_MCP_ALLOWED_TOOLS`, `KC_MCP_DENIED_TOOLS`, `KC_MCP_ALLOWED_CATEGORIES` narrow the tool set explicitly.
* **Role filtering** (`kc-mcp.role-filter`, on by default): every tool declares the roles it needs
  (`ToolSpec.roles(...)`): `view-users` is shorthand for the `realm-management` client role, `my-app.auditor` is a
  role of another client (split at the last dot), `realm:support` is a realm role. Realm-management roles follow
  Keycloak's implications (`manage-x` covers `view-x` covers `query-x`, `realm-admin` covers all); custom client and
  realm roles are checked in the token of the auth realm. The server inspects its own access token and hides tools whose roles it lacks
  from listing and search; a direct call answers `forbidden` with the missing role, without a round trip. Tokens
  without any admin roles switch the filter off rather than hiding everything.
* DESTRUCTIVE tools (delete user/group, reset password, logout, unassign roles, …) ask the human through MCP
  elicitation when the client supports it; otherwise they require `confirm: true` and explain that in the error.
* `keycloak_user_delete` additionally requires the matching `username`; `keycloak_realm_update` and
  `keycloak_auth_flow_bind` count as destructive because they can lock people out.
* One audit log line per executed tool (`org.keycloak.mcp.audit`).

## Access levels

The real boundary is always the service account's roles in Keycloak; the server flags are a second layer.

| level          | Keycloak side | server side |
|----------------|---------------|-------------|
| full admin     | client in `master` with `admin`, or the admin user via `admin-cli` | nothing to set |
| realm admin    | confidential client **in the realm** with `realm-admin` | `KC_MCP_ALLOWED_REALMS=<realm>`, `KC_MCP_DEFAULT_REALM=<realm>` |
| realm manager  | client in the realm with just the `realm-management` roles needed, e.g. `view-users`, `manage-users` | same as realm admin; role filtering hides the rest automatically. Narrow further with `KC_MCP_DENIED_TOOLS=keycloak_user_delete` or `KC_MCP_READ_ONLY=true` |

A client in `master` can also manage other realms through the `<realm>-realm` client roles; the role filter
understands both layouts.

### Per-tool access checks and delegation

Beyond roles, a tool can carry extra predicates and a delegation rule:

```java
tool("keycloak_user_delete")
    .roles("manage-users")
    .access(ctx -> ctx.arg("username").startsWith("svc-")
            ? AccessCheck.Decision.deny("protected_user", "service users are deleted by the platform team")
            : AccessCheck.Decision.allow())
    .delegation(Delegation.ALLOWED)   // ALLOWED (default) | FORBIDDEN | REQUIRED
```

`AccessCheck` receives the tool, the resolved realm, the validated arguments, the server's granted roles and the
`Caller`. Checks run after the realm allow-list and role checks and before the confirmation step; a denial is
returned as `{"error": <code>, "message": ...}`. A `ToolProvider` can also contribute checks that apply to every
tool through `accessChecks(...)`, as can any CDI bean implementing `AccessCheck`.

`Delegation` says whether a tool may run when the server acts on behalf of a user instead of with its own service
account (see `sketch/notes/delegated-auth.md`). Until the endpoint authenticates callers, the `Caller` is anonymous
and not delegated, so `FORBIDDEN` tools behave normally and `REQUIRED` tools are refused. Tools that reveal secrets
or reshape the realm default to `FORBIDDEN`: `client_get_secret`, `client_regenerate_secret`, `realm_update`,
`auth_flow_bind`, `federation_sync`.

### Built-in policies: group scope and no escalation

The `policies` provider ships two caller-relative checks (off by default for anonymous callers; they act once the
endpoint authenticates callers, see §Callers):

| setting (`kc-mcp.spi.policies.*`) | default | meaning |
|---|---|---|
| `group-scope` | `off` | `group`: a caller may only manage groups they are a member of (or subgroups); `organization`: groups of the caller's organizations |
| `manager-role` | | role the caller needs for group management, e.g. `realm:group-manager` |
| `no-escalation` | `true` | callers may only grant roles (directly, via client roles, group mappings or group membership) within their own effective roles, may not touch users who outrank them, and may not grant to themselves |
| `anonymous` | `allow` | `deny` refuses the guarded tools when no caller is known |
| `super-roles` | `realm:admin, realm-management.realm-admin` | callers holding one of these bypass both checks |

Denials come back as `group_out_of_scope`, `manager_role_required`, `privilege_escalation`,
`target_outranks_caller`, `self_grant`, `caller_unknown`, `caller_foreign_realm` or `caller_required`.
Effective roles are computed from Keycloak (direct, group-inherited and composite-expanded).

### Callers

Who is acting comes from the request's Quarkus `SecurityIdentity`: with the MCP endpoint protected by
`quarkus-mcp-server-oidc`, the caller's token provides subject, username, issuing realm and roles
(`CallerProvider`). Until then the caller is anonymous. Delegated execution (token exchange, acting with the
caller's own permissions) is prepared through `Caller.delegated()` and the per-tool `Delegation` setting but not
wired yet.

## Several Keycloak systems

One server can front several Keycloak installations. Declare them under `kc-mcp.systems.<name>.*`; every field
falls back to the top-level value, so shared settings are written once:

```properties
kc-mcp.grant-type=client_credentials
kc-mcp.client-id=mcp-admin
kc-mcp.systems.prod.url=https://sso.example.com
kc-mcp.systems.prod.client-secret=${PROD_SECRET}
kc-mcp.systems.prod.allowed-realms=customers,partners
kc-mcp.systems.staging.url=https://sso-staging.example.com
kc-mcp.systems.staging.client-secret=${STAGING_SECRET}
kc-mcp.default-system=prod
```

With more than one system every tool gains a `system` argument (a closed enum of the names, optional when a
default system is set). Roles, allowed realms, default realm, startup checks and the audit log are tracked per
system; one `private_key_jwt` key serves all of them. Without `kc-mcp.systems.*` the top-level settings form a
single system called `default` and no `system` argument appears.

When you prefer one process per Keycloak, `kc-mcp.tool-prefix=prod_` renames the tools
(`prod_keycloak_user_search`) so MCP clients that merge several servers keep them apart; `execute_tool` and the
config lists accept both spellings.

## Configuration

Every property maps to an environment variable (`kc-mcp.grant-type` → `KC_MCP_GRANT_TYPE`).

| property                        | default                     | meaning |
|---------------------------------|-----------------------------|---------|
| `kc-mcp.url`                    | `http://localhost:8080`     | Keycloak base URL; include a context path if there is one, e.g. `https://sso.example.com/auth` |
| `kc-mcp.grant-type`             | `client_credentials`        | `client_credentials` or `password` |
| `kc-mcp.client-auth`            | inferred                    | `client_secret`, `private_key_jwt` or `none`; inferred from what is configured |
| `kc-mcp.auth-realm`             | `master`                    | realm the client / admin user lives in |
| `kc-mcp.client-id`              | `admin-cli` for password+none | client id |
| `kc-mcp.client-secret`          |                             | for `client_secret` |
| `kc-mcp.jwt.key-file`           |                             | PKCS#8 PEM private key for `private_key_jwt` |
| `kc-mcp.jwt.keystore-file` / `keystore-password` / `key-alias` / `key-password` / `keystore-type` | | keystore alternative |
| `kc-mcp.jwt.algorithm`          | `RS256`                     | RS256/384/512, PS256/384/512, ES256/384/512 |
| `kc-mcp.jwt.key-id`             | JWK thumbprint              | `kid` in the assertion header and the JWKS |
| `kc-mcp.jwt.public-key-file`    | derived                     | public key / certificate PEM to publish; derived from the private key when unset |
| `kc-mcp.jwt.jwks-enabled` / `jwks-path` | `true` / `/.well-known/jwks.json` | serve the public key as a JWK Set |
| `kc-mcp.username` / `password`  |                             | for the password grant |
| `kc-mcp.default-realm`          |                             | makes the `realm` argument optional |
| `kc-mcp.systems.<name>.*`       |                             | per-system `url`, `grant-type`, `client-auth`, `auth-realm`, `client-id`, `client-secret`, `username`, `password`, `default-realm`, `allowed-realms` |
| `kc-mcp.default-system`         | the only system             | system used when the `system` argument is omitted |
| `kc-mcp.tool-prefix`            |                             | prefix for all tool names, e.g. `prod_` |
| `kc-mcp.allowed-realms`         | all                         | csv allow-list |
| `kc-mcp.read-only`              | `false`                     | |
| `kc-mcp.allowed-tools` / `denied-tools` / `allowed-categories` | all | explicit narrowing of the tool set |
| `kc-mcp.role-filter`            | `true`                      | hide/refuse tools the token's realm-management roles do not cover |
| `kc-mcp.startup-check`          | `warn`                      | `warn`, `fail` or `off`: verify allowed realms are reachable at startup |
| `kc-mcp.tool-exposure`          | `hybrid`                    | `direct` / `lazy` / `hybrid` / `progressive` |
| `kc-mcp.hot-tools`              | user_search, user_get, realm_get_config, server_info | listed directly in hybrid mode |
| `kc-mcp.search-limit-default`   | `5`                         | hits per `search_tools` call (max 10) |
| `kc-mcp.result-max-items`       | `100`                       | cap for list results |
| `kc-mcp.confirm-timeout-seconds`| `120`                       | elicitation timeout |
| `kc-mcp.spi.<provider>.<key>`   |                             | per tool-provider settings, `enabled=false` disables one |

Examples:

```properties
# service account with a secret (recommended)
kc-mcp.client-id=mcp-admin
kc-mcp.client-secret=...

# service account with private_key_jwt
kc-mcp.client-id=mcp-admin
kc-mcp.jwt.key-file=/etc/keycloak-mcp/mcp-admin.pem

# Keycloak side for private_key_jwt: client mcp-admin -> Credentials -> Client Authenticator "Signed JWT",
# "Use JWKS URL" = on, JWKS URL = https://<this server>/.well-known/jwks.json (served automatically in this mode;
# alternatively import the key printed by that endpoint). The assertion's kid matches the JWK's kid.

# local dev: admin user via admin-cli
kc-mcp.grant-type=password
kc-mcp.username=admin
kc-mcp.password=admin
```

The server listens on port 8081 (`quarkus.http.port`) so a local Keycloak can keep 8080; the MCP endpoint is
`http://localhost:8081/mcp`. See `sketch/notes/keycloak-setup.md` for the roles the service account needs.

## Extending: tool providers

Tools come from `org.keycloak.mcp.spi.ToolProvider` implementations, discovered like Keycloak providers:

```java
public class AcmeToolProvider implements ToolProvider {
    public String id() { return "acme"; }
    public String displayName() { return "ACME tools"; }
    public String description() { return "Company specific helpers."; }

    public List<ToolSpec> tools(ToolProviderContext ctx) {
        KeycloakAdmin kc = ctx.keycloak();                 // shared admin client + lookup helpers
        String greeting = ctx.config().get("greeting", "hi"); // kc-mcp.spi.acme.greeting
        return List.of(ToolSpec.builder("keycloak_acme_ping")
                .title("ACME ping").description("Says hello.")
                .category(Category.REALM).read().global()
                .synonyms("acme", "ping")
                .schema(InputSchema.builder().string("name", "Who to greet"))
                .handler(call -> ToolResult.ok(Map.of("greeting", greeting, "name", call.str("name", "world"))))
                .build());
    }
}
```

Register it in `META-INF/services/org.keycloak.mcp.spi.ToolProvider` (or make it a CDI bean). Jars placed in
`target/quarkus-app/providers/` are picked up at startup (`quarkus.package.jar.user-providers-directory`).
Provider tools automatically get search, exposure modes, validation, realm checks, confirmation and the audit log.
The built-in areas (`users`, `groups`, `roles`, `clients`, `idp`, `orgs`, `federation`, `auth-flows`, `events`,
`realm`) use the same SPI and can be switched off with `kc-mcp.spi.<id>.enabled=false`.

## Keeping the tools aligned with a Keycloak version

Every tool declares the Admin REST operations it relies on (`ToolSpec.api(...)`, see `ApiOperation`): method and
path, which tool argument fills which path or query parameter, and which fields of the request body it writes.
`OpenApiAlignmentTest` checks all of that against the published OpenAPI document of a concrete server version in
`src/test/resources/openapi/keycloak-<version>.json` (26.8.1 is checked in): the operation must exist and not be
deprecated, parameters and body fields must exist with compatible types and enums. Spec parameters a tool does not
expose are printed as a drift report. To check another version:

```shell
curl -o src/test/resources/openapi/keycloak-26.9.0.json https://www.keycloak.org/docs-api/26.9.0/rest-api/openapi.json
./mvnw test -Dtest=OpenApiAlignmentTest -Dkeycloak.openapi.version=26.9.0
```

Two endpoints we use are missing from the published document (server info, user storage sync); they are marked
`unspecified` with a reason. The Java admin client itself is versioned independently of the server since Keycloak
26.1, so this test, together with the Testcontainers run, is what ties the tool surface to a server version.

## Running

```shell
./mvnw quarkus:dev                     # dev mode, MCP endpoint on http://localhost:8081/mcp
./mvnw test                            # unit + in-process MCP endpoint tests (no Keycloak needed)
./mvnw verify -DskipITs=false          # + Testcontainers Keycloak 26.8.1 integration test
./mvnw package && java -jar target/quarkus-app/quarkus-run.jar
```

LM Studio (`mcp.json`):

```json
{ "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp" } } }
```

## Tool areas

| category        | tools |
|-----------------|-------|
| users, sessions | search, get, create, update, set_enabled, delete, reset_password, send_action_email, sessions_list, logout |
| groups          | list, create, delete, members_list, member_add, member_remove, user_groups_list, role_assign |
| roles           | role_list, client_roles_list, user_roles_get, user_role_assign/unassign, user_client_roles_get, user_client_role_assign/unassign |
| clients, scopes | list, get, get_secret, regenerate_secret, create, update, delete, mappers_list, scopes_list, default_scopes_get, scope_assign/unassign |
| idp             | list, get, mappers_list, create, delete |
| orgs            | list, get, create, delete, idp_list, idp_link, idp_unlink |
| federation      | list, get, sync |
| auth flows      | flows_list, executions_list, authenticator_providers_list, flow_create/copy/bind, execution_add/update/raise/lower/delete, subflow_add, required_actions_list, required_action_set_enabled |
| events          | events_login, events_admin |
| realm           | server_info, realm_get_config, realm_update |

## Roadmap

See `sketch/notes/implementation-plan.md`. Next: model-in-the-loop benchmarks with LM Studio (turns to success,
tool-choice errors, tokens per mode), optional OIDC protection of the endpoint, the reference project's skill
recipes as MCP prompts, a federation sync test against a real LDAP, and `private_key_jwt` against a Keycloak
client configured for JWT authentication.

## Quarkus notes

Dev UI: <http://localhost:8081/q/dev/>. Native image: `./mvnw package -Dnative` (untested so far).
