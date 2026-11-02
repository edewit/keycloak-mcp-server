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
* `KC_MCP_ALLOWED_REALMS=a,b` restricts every call to those realms.
* DESTRUCTIVE tools (delete user/group, reset password, logout, unassign roles, …) ask the human through MCP
  elicitation when the client supports it; otherwise they require `confirm: true` and explain that in the error.
* `keycloak_user_delete` additionally requires the matching `username`; `keycloak_realm_update` and
  `keycloak_auth_flow_bind` count as destructive because they can lock people out.
* One audit log line per executed tool (`org.keycloak.mcp.audit`).

## Configuration

Every property maps to an environment variable (`kc-mcp.grant-type` → `KC_MCP_GRANT_TYPE`).

| property                        | default                     | meaning |
|---------------------------------|-----------------------------|---------|
| `kc-mcp.url`                    | `http://localhost:8080`     | Keycloak base URL |
| `kc-mcp.grant-type`             | `client_credentials`        | `client_credentials` or `password` |
| `kc-mcp.client-auth`            | inferred                    | `client_secret`, `private_key_jwt` or `none`; inferred from what is configured |
| `kc-mcp.auth-realm`             | `master`                    | realm the client / admin user lives in |
| `kc-mcp.client-id`              | `admin-cli` for password+none | client id |
| `kc-mcp.client-secret`          |                             | for `client_secret` |
| `kc-mcp.jwt.key-file`           |                             | PKCS#8 PEM private key for `private_key_jwt` |
| `kc-mcp.jwt.keystore-file` / `keystore-password` / `key-alias` / `key-password` / `keystore-type` | | keystore alternative |
| `kc-mcp.jwt.algorithm`          | `RS256`                     | RS256/384/512, PS256/384/512, ES256/384/512 |
| `kc-mcp.jwt.key-id`             |                             | optional `kid` header |
| `kc-mcp.username` / `password`  |                             | for the password grant |
| `kc-mcp.default-realm`          |                             | makes the `realm` argument optional |
| `kc-mcp.allowed-realms`         | all                         | csv allow-list |
| `kc-mcp.read-only`              | `false`                     | |
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
