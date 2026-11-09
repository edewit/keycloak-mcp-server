# Development

[keycloak-mcp-server](../README.md) › documentation

Building, running and testing the server; the modules; formatting; open items.

```shell
./mvnw quarkus:dev -pl modules/backend -am      # dev mode, http://localhost:8081/mcp
./mvnw test                                     # unit + in-process MCP tests, no Keycloak
./mvnw verify -DskipITs=false                   # + Testcontainers Keycloak 26.8.2, + storage IT on Dev Services PostgreSQL
./mvnw package && java -jar modules/backend/target/quarkus-app/quarkus-run.jar start
./mvnw package -Ppostgresql                     # PostgreSQL build
./mvnw spotless:apply                           # format; `verify` fails on unformatted code
conformance/run.sh                              # MCP conformance suite against the packaged server (conformance/README.md)
```

Modules under `modules/`:

- `api`: `keycloak-mcp-server-api`, extension SPI, no Quarkus, packages `com.github.thomasdarimont.keycloak.mcp`
- `storage`: `keycloak-mcp-server-storage`, Liquibase changelog, `...mcp.storage` (switch, startup log), `.crypto`,
  `.systems`, `.keys`, `.audit`
- `backend`: `keycloak-mcp-server-backend`, Quarkus application, `...mcp.backend`
- `distribution`: `keycloak-mcp-server-distribution`, the downloadable `keycloak-mcp-server-<version>.tar.gz` and `.zip`
  (`bin/kcmcp.sh`, `bin/kcmcp.bat`, `conf/kcmcp.conf` with the `conf/scenarios/` templates, the server under `lib/`, `providers/`,
  `data/`, `docs/`), assembled from `modules/distribution/src/main/content` and the backend's `quarkus-app` by
  `./mvnw package -Pdist` (the module is behind the `dist` profile; the default build stops at the jars)

## Releases

A tag `v<version>` pushed to GitHub runs `.github/workflows/release.yml`: it sets the version from the tag for the
build, runs the full verification, and publishes a GitHub release with the two archives attached. The CI workflow
unpacks the archive and starts it with `kcmcp.sh` on Linux and `kcmcp.bat` on Windows on every push.

Dev mode needs `-pl modules/backend -am`; other goals run from the root. The tests ignore `KC_MCP_*` and `QUARKUS_*`
variables of the shell (the root pom clears every variable the examples define), so a shell that sourced an example's
env file still runs the suite; `quarkus:dev` and the packaged server do honour them. `StorageTest` (backend, in-memory H2) always runs.
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

Dev UI <http://localhost:8081/q/dev/>; Swagger UI for the admin API <http://localhost:8081/q/swagger-ui/> and the
document at `/q/openapi` are in every build. The server runs on the JVM only: extension jars are loaded from `providers/` at
runtime, the default storage is the embedded H2, and the storage derives keys with Bouncy Castle, none of which fits a
GraalVM native image. The Quarkus native profile and Dockerfiles were removed for that reason; `Dockerfile.jvm` is the
one container build.
