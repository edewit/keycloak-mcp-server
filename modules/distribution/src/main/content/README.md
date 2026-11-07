# keycloak-mcp-server

An MCP server for Keycloak administration: an AI assistant manages users, groups, roles, clients, identity providers,
organizations, authentication flows, events and realm settings through it, within the roles you give it. The full
documentation is in `docs/`, starting with `docs/README.md`.

## Start

Needs Java 21 or newer.

1. Tell the server which Keycloak to use and how to authenticate: edit `conf/kcmcp.conf`, or pick a complete setup
   from `conf/scenarios/` and change the URL and secret in it.
2. Start it:

   ```shell
   bin/kcmcp.sh start                                            # conf/kcmcp.conf
   bin/kcmcp.sh start --config conf/scenarios/service-account.conf
   bin\kcmcp.bat start --config conf\scenarios\service-account.conf    # Windows
   ```

3. Point an MCP client at `http://localhost:8081/mcp` (`docs/integrations.md` has the settings for LM Studio, Claude
   Code, VS Code, Cursor and others). With a user login, the client opens the browser and the user signs in at Keycloak.

Any setting can go on the command line (`--kc-mcp.url=https://sso.example.com`, `--quarkus.http.port=8082`) or into
the environment (`KC_MCP_URL`). `bin/kcmcp.sh --help` lists the options, `--debug [port]` opens a debugger port.

## Scenarios

| file in `conf/scenarios/` | setup |
|---|---|
| `local-admin.properties` | the Keycloak admin user, every realm; local demos only |
| `service-account.properties` | a confidential client inside the realm with the roles it needs; the usual single-realm setup |
| `read-only.properties` | a view-only service account plus the read-only switch |
| `private-key-jwt.properties` | the service account authenticates with a signed JWT instead of a secret |
| `several-systems.properties` | several Keycloak installations from one server, each tool with a `system` argument |
| `user-login.properties` | users log in through their MCP client; every call runs with their own roles |
| `shared-server.properties` | a server for a team or environment: user login plus the `shared` security profile |
| `dynamic-systems.properties` | no Keycloak configured; systems are registered through the admin API, each with a generated key and its own JWKS |

## Layout

| directory | holds |
|---|---|
| `bin/` | `kcmcp.sh`, `kcmcp.bat` |
| `conf/` | `kcmcp.conf`, `scenarios/`, `systems/` (one file per Keycloak system), your keys and certificates |
| `lib/` | the server (Quarkus fast-jar layout); nothing to edit |
| `providers/` | extension jars, loaded at startup |
| `data/` | the embedded database, per-system keys, logs |
| `docs/` | the documentation |

## Container

The same server is available as a container image built from the repository (`modules/backend/src/main/docker/`);
the examples there run it with Docker Compose next to a Keycloak.
