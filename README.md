# keycloak-mcp-server

[![CI](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant administer Keycloak: users, groups, roles,
clients, identity providers, organizations, authentication flows, events and realm settings. A comprehensive set of tools over the Admin
REST API (after [mcp-keycloak-admin](https://github.com/edewit/mcp-keycloak-admin)), built with Quarkus for Keycloak 26.8,
reached over streamable HTTP, and shaped so that small local models can use them too.

The intended setup is **one shared MCP server per environment**: one for dev, one for test, one for QA, one for
production, each in front of the Keycloak systems of that environment (several installations, tenants, clusters) and
their realms. Users log in to it through their MCP client, every Admin API call runs with their own roles, and
policies, confirmations and audit sit in one place instead of on every laptop. The server itself holds no state: systems,
keys, secrets, UI sessions, pending approvals and the audit trail live in a shared database
([Database storage](docs/storage.md), PostgreSQL for several instances), so it can be deployed in a HA setup behind a
load balancer that keeps an MCP session on the instance that opened it ([Several instances](docs/storage.md#several-instances-on-one-database)).
The same server also runs locally for a single administrator, which is where the quick start below begins.

- **Several Keycloak systems per server.** The systems of an environment are configured or registered at runtime,
  each with its own signing key; the model names the system, or a client gets an MCP entry bound to one system or
  realm. The `shared` profile refuses to start without authentication and the other settings a server other people
  reach needs.
- **The user's own identity, or a service account.** Users log in through their MCP client, so every Admin API call
  runs with their own token and Keycloak enforces their roles; destructive tools can be approved on the user's own
  device through CIBA. A service account is the alternative for a local or single-purpose setup.
- **Guardrails by default.** Destructive tools need a confirmation, every call is audited with secrets redacted, roles
  the identity lacks hide the tools they would need, and allow-lists fence in realms, hosts and tools.
- **Small models cope.** By default the model sees three tools: `whoami`, `search_tools` and `execute_tool`. It searches
  for what it needs ("kick a user" finds the logout tool), identifiers are forgiving (user by id or username, group by
  path), errors are structured and results compact.
- **Extensible.** An SPI for your own tools, prompts, access checks, confirmers, audit sinks and system registries,
  loaded from a jar.

## Quick start

The shortest path is local: one Keycloak, the server on your machine with a service account. Needs Java 21 and Docker.

1. Start the demo Keycloak (realm `demo` with users, groups and a service account for the server):

   ```shell
   cd examples/run-modes && docker compose up -d && cd ../..
   ```

2. Run the server as a realm admin of that realm:

   ```shell
   set -a; source examples/run-modes/env/realm-admin.env; set +a
   ./mvnw quarkus:dev -pl modules/backend -am        # MCP endpoint: http://localhost:8081/mcp
   ```

3. Connect an MCP client to `http://localhost:8081/mcp`:

   - LM Studio: add `examples/run-modes/mcp.json` to its MCP settings:
     ```json
     { "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp" } } }
     ```
   - Claude Code: `claude mcp add --transport http keycloak http://localhost:8081/mcp`
   - VS Code, Cursor, Codex, Claude Desktop and the login setup: [Integrations](docs/integrations.md)

4. Ask it something: "who am I", "find users named ali", "which groups is alice in", "disable bob".

The other access levels (full admin, realm manager, read-only, two systems, `private_key_jwt`, the user's own login) are
one env file away, see [examples/run-modes](examples/run-modes/README.md).

**Without a build:** the [releases](https://github.com/thomasdarimont/keycloak-mcp-server/releases) carry a
`keycloak-mcp-server-<version>.tar.gz` and `.zip`. Unpack, edit `conf/kcmcp.conf` or copy a ready-made setup from
the templates in `conf/scenarios/`, and start with `bin/kcmcp.sh start` (`bin\kcmcp.bat` on Windows); the archive's
README explains the layout. `./mvnw package -Pdist` builds the same archives into `modules/distribution/target/`.

For a shared server per environment, start from `examples/run-modes/env/shared.env` (users log in, profile `shared`) and read
[Security](docs/security.md) for what the profile requires, [Several Keycloak systems](docs/systems.md) for adding
systems and per-system entries, and [multi-tenant](examples/multi-tenant/) or [dynamic-systems](examples/dynamic-systems/)
for a complete stack.

## How it works

- **The model's view.** `tools/list` depends on the exposure mode: `hybrid` (default) lists `search_tools`,
  `execute_tool`, `whoami` and a few hot tools; `direct` lists every tool. `whoami` tells the model who it acts as and
  which tools that unlocks. [Tools](docs/tools.md)
- **One pipeline for every call.** Access policy, argument validation, realm check, confirmation, the handler, audit.
  Errors are structured (`unknown_tool`, `invalid_arguments`, `forbidden`, `confirmation_required`, ...) and say what
  to do next. [Tools](docs/tools.md), [Security](docs/security.md)
- **Keycloak's roles are the boundary.** The server acts with a service account or with the signed-in user's token;
  the `realm-management` roles of that identity decide what works, server flags only narrow further.
  [Security](docs/security.md)
- **Destructive tools ask first.** Through the client's elicitation, a `confirm: true` flag (local profile), an own
  `Confirmer` such as a ticket check, or CIBA on the user's device. [CIBA confirmation](docs/ciba-confirmation.md)

## Documentation

| page | what it covers |
|---|---|
| [Tools](docs/tools.md) | what the model sees, the tool areas, prompts |
| [Integrations](docs/integrations.md) | adding the server to LM Studio, Claude Code, Claude Desktop, VS Code and Copilot, Cursor, Codex; the login's Keycloak side |
| [Security](docs/security.md) | guardrails, profiles `local` and `shared`, access levels, per-tool checks, policies, callers and delegation |
| [Configuration](docs/configuration.md) | every property with default and meaning |
| [Several Keycloak systems](docs/systems.md) | static and dynamic systems, per-system keys, the admin API, one MCP entry per system or realm |
| [Database storage](docs/storage.md) | H2 or PostgreSQL for systems, keys, secrets, audit and sessions; encryption and key rotation |
| [Management UI](docs/management-ui.md) | the browser UI and its backend-for-frontend; work in progress, a login skeleton today |
| [CIBA confirmation](docs/ciba-confirmation.md) | approval of destructive tools on the user's device |
| [Metrics](docs/metrics.md) | OpenTelemetry metrics and what they answer |
| [Extending](docs/extending.md) | the extension SPI: tools, prompts, checks, confirmers, audit listeners, extension jars |
| [Supported Keycloak versions](docs/keycloak-versions.md) | baseline, feature and version requirements, OpenAPI alignment |
| [Development](docs/development.md) | build, test, modules, formatting, roadmap |

## Examples

Each example is a `docker compose` stack with a README and a scripted walkthrough.

| example | shows |
|---|---|
| [run-modes](examples/run-modes/) | one Keycloak, a demo realm, one env file per access level; the place to start |
| [multi-tenant](examples/multi-tenant/) | two tenants as systems, keys per tenant, one MCP entry per tenant or realm, user login per realm |
| [dynamic-systems](examples/dynamic-systems/) | no system at startup; registration through the admin API into PostgreSQL with a generated key |
| [delegated-auth](examples/delegated-auth/) | the server as a delegated agent (`KC_MCP_DELEGATION=exchange`) with Keycloak's token exchange delegation |
| [ciba-confirm](examples/ciba-confirm/) | destructive tools approved on the user's device, with an approver app standing in for the phone |
| [management-ui](examples/management-ui/) | the management UI with one or two identity providers |
| [extensions](examples/extensions/) | an extension jar: tools, prompt, confirmer, access check, audit listener, scrubber, system repository |
| [distribution](examples/distribution/) | the packaged server from the `.tar.gz` against a Keycloak in Docker: users log in through LM Studio, `private_key_jwt`, a system entry and a realm entry |

## Development

```shell
./mvnw test                                     # unit + in-process MCP tests, no Keycloak
./mvnw verify -DskipITs=false                   # + integration tests against Keycloak 26.8.2 in Docker
./mvnw spotless:apply                           # format; `verify` fails on unformatted code
conformance/run.sh                              # MCP conformance suite against the packaged server
```

Modules: `api` (extension SPI, no Quarkus), `storage` (database), `frontend` (management UI), `backend` (the Quarkus
application), `distribution` (the downloadable archives). More in [Development](docs/development.md), including the
roadmap.
