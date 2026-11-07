# Development

[keycloak-mcp-server](../README.md) › documentation

Building, running and testing the server; the modules; formatting; open items.

```shell
./mvnw quarkus:dev -pl modules/backend -am      # dev mode, http://localhost:8081/mcp
./mvnw test                                     # unit + in-process MCP tests, no Keycloak
./mvnw verify -DskipITs=false                   # + Testcontainers Keycloak 26.8.2, + storage IT on Dev Services PostgreSQL
./mvnw package && java -jar modules/backend/target/quarkus-app/quarkus-run.jar
./mvnw package -Ppostgresql                     # PostgreSQL build
./mvnw spotless:apply                           # format; `verify` fails on unformatted code
conformance/run.sh                              # MCP conformance suite against the packaged server (conformance/README.md)
```

Modules under `modules/`:

- `api`: `keycloak-mcp-server-api`, extension SPI, no Quarkus, packages `com.github.thomasdarimont.keycloak.mcp`
- `storage`: `keycloak-mcp-server-storage`, Liquibase changelog, `...mcp.storage` (switch, startup log), `.crypto`,
  `.systems`, `.keys`, `.audit`
- `backend`: `keycloak-mcp-server-backend`, Quarkus application, `...mcp.backend`

Dev mode needs `-pl modules/backend -am`; other goals run from the root. `StorageTest` (backend, in-memory H2) always runs.
IntelliJ: `.run/` holds run configurations for every example and the conformance suite (`examples/gen-run-configs.sh`).

Formatting: [Spotless](https://github.com/diffplug/spotless), [Spring Java Format](https://github.com/spring-io/spring-javaformat)
with spaces (`etc/eclipse-formatter.prefs`; imports `java|javax|jakarta`, `org`, `com`, rest, static).

## Status and roadmap

Status: all reference tools, search, exposure modes, guardrails, extension SPI, database storage, admin API and the
management UI bootstrap (login, sessions, BFF) done; the UI pages themselves are still to come. Open items:

- Model-in-the-loop benchmarks with LM Studio: turns to success, tool-choice errors, tokens per mode
- Reference skill recipes as prompts
- Federation sync test against a real LDAP
- `private_key_jwt` against a JWT-authenticated Keycloak client
- Admin API read access to audit rows and signing-key history
- Management UI pages for systems, secrets and the audit trail (today: a login skeleton)

## Quarkus notes

Dev UI <http://localhost:8081/q/dev/>. Native: `./mvnw package -Dnative` (untested).
