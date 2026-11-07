# Configuration

[keycloak-mcp-server](../README.md) › documentation

Every property, its default and meaning. Property → environment variable: `kc-mcp.grant-type` → `KC_MCP_GRANT_TYPE`.

| property                        | default                     | meaning |
|---------------------------------|-----------------------------|---------|
| `kc-mcp.url`                    | `http://localhost:8080`     | Keycloak base URL, context path included (`https://sso.example.com/auth`) |
| `kc-mcp.grant-type`             | `client_credentials`        | `client_credentials`, or `password` (deprecated by OAuth 2.1; local dev, static configuration only) |
| `kc-mcp.client-auth`            | inferred                    | `client_secret`, `private_key_jwt`, `none` |
| `kc-mcp.auth-realm`             | `master`                    | realm of the client / admin user |
| `kc-mcp.client-id`              | `admin-cli` for password+none | client id |
| `kc-mcp.client-secret`          |                             | for `client_secret` |
| `kc-mcp.jwt.key-file`           |                             | PKCS#8 PEM private key for `private_key_jwt` |
| `kc-mcp.jwt.keystore-file` / `keystore-password` / `key-alias` / `key-password` / `keystore-type` | | keystore alternative |
| `kc-mcp.jwt.algorithm`          | `RS256`                     | RS256/384/512, PS256/384/512, ES256/384/512 |
| `kc-mcp.jwt.key-id`             | JWK thumbprint              | `kid` in assertion header and JWKS |
| `kc-mcp.jwt.public-key-file`    | derived                     | public key / certificate PEM to publish |
| `kc-mcp.jwt.jwks-enabled` / `jwks-path` | `true` / `/.well-known/jwks.json` | configured key (else default system's) at `jwks-path`; every system at `/auth/keys/<system>/jwks.json` |
| `kc-mcp.jwt.key-size`           | `2048`                      | RSA modulus bits of generated keys; algorithm decides RSA vs EC curve |
| `kc-mcp.dynamic-systems`        | `false`                     | let `KeycloakSystemRepository`s add systems |
| `kc-mcp.systems-file`           |                             | JSON file (`{"systems": [...]}`) of the file repository, re-read on change; needs `dynamic-systems` |
| `kc-mcp.static-systems-order`   | `-1000`                     | rank of static configuration among repositories (lower first, repositories default 0) |
| `kc-mcp.static-systems`         | `true`                      | `false`: repositories only |
| `kc-mcp.keys-dir`               | `data/keys`                 | read-only built-in `KeyVault`: `<system>.pem`, `secrets/<name>` |
| `quarkus.datasource.jdbc.url`   |                             | turns database storage on: `jdbc:h2:file:./data/kc-mcp`, or `jdbc:postgresql://...` in a `-Ppostgresql` build (+ `quarkus.datasource.username`/`password`) |
| `kc-mcp.storage.enabled`        | `true` with a jdbc url      | force storage on or off |
| `kc-mcp.storage.secret-key`     |                             | AES-256-GCM key for stored private keys, client secrets, passwords; base64 of 32 bytes or passphrase (Argon2id) |
| `kc-mcp.storage.previous-secret-keys` |                       | rotated-away keys (csv) that still decrypt; rows are rewritten under `secret-key` at startup and by `POST /admin/storage/rekey` |
| `kc-mcp.spi.pii-audit-scrubber.pseudonym-key` | `secret-key`   | HMAC key of the audit pseudonyms, independent of storage key rotation |
| `kc-mcp.admin.enabled` / `token` / `issuer` / `audience` / `role` | `false` / / / / `realm:admin` | admin API at `/admin`: static token and/or trusted issuer with role |
| `kc-mcp.admin.allow-new-systems` | `true`                     | `false`: the admin API changes known systems only, new aliases answer 403 `registration_closed` |
| `kc-mcp.spi.db-systems.cache-seconds` | `10`                  | snapshot age of stored systems |
| `kc-mcp.spi.db-audit.retention-days` |                        | delete audit rows older than this (startup, then hourly); unset keeps all |
| `kc-mcp.spi.db-key-vault.retired-key-grace-seconds` | `3600`    | how long a rotated-away key stays in the JWKS |
| `kc-mcp.spi.pii-audit-scrubber.pii` | `keep`                  | `keep`, `pseudonymize`, `drop`; `pii-args` argument names, `targets` listeners (default `db-audit`) |
| `kc-mcp.username` / `password`  |                             | password grant (static configuration only) |
| `kc-mcp.delegation`             | `off`                       | `forward`: calls run with the caller's token; `exchange`: with a delegated token Keycloak issues for caller + server client (26.8 token exchange delegation); both need `quarkus.oidc.tenant-enabled=true` |
| `kc-mcp.admin-api-scope`        | `kc-admin-api`              | scope requested with Admin API tokens and advertised to MCP clients (Keycloak 26.8.2+ audience check); dropped on `invalid_scope`; blank: none |
| `kc-mcp.dns-rebinding-protection` | `auto`                    | `auto` (on while anonymous), `on`, `off`: `Host`/`Origin` of MCP requests must be localhost or in `kc-mcp.dns-rebinding-allowed-hosts` |
| `kc-mcp.profile`                | `local`                     | `local` or `shared`: defaults of the four rows below, and `shared` refuses to start without caller authentication + audience, `allowed-hosts`, admin audience, storage `secret-key` ([Guardrails](security.md#guardrails)) |
| `kc-mcp.require-caller`         | `false`, `shared`: always   | refuse anonymous requests with the OAuth challenge even with `delegation=off` |
| `kc-mcp.confirm-fallback`       | `flag`, `shared`: `deny`    | without elicitation: `flag` accepts `confirm: true`, `deny` refuses destructive tools |
| `kc-mcp.explicit-target`        | `off`, `shared`: `destructive` | `destructive` or `write` tools must pass `system` (several systems) and `realm` instead of the defaults |
| `kc-mcp.dynamic-private-hosts`  | `allow`, `shared`: `listed` | `listed`: a runtime-registered system on a private, loopback or link-local address needs its host named literally in `allowed-hosts` |
| `kc-mcp.model-confirmation`     | `auto`                      | guidance to the model about destructive tools: `ask`, `server`, `auto` ([Guardrails](security.md#guardrails)) |
| `kc-mcp.model-confirmation-trusted-roles` |                   | role refs whose holders are told to pass `confirm: true` right away in `ask` mode |
| `quarkus.oidc.tenant-enabled`   | `false`                     | verify bearer tokens; issuer `${kc-mcp.url}/realms/${kc-mcp.auth-realm}` |
| `quarkus.oidc.token.audience`   |                             | required `aud` (recommended with `forward`) |
| `quarkus.oidc.token.issuer`     |                             | public issuer when `kc-mcp.url` is internal (Docker) |
| `quarkus.oidc.resource-metadata.authorization-server` | `quarkus.oidc.auth-server-url` | login address MCP clients are sent to; the public issuer when `kc-mcp.url` is internal |
| `kc-mcp.default-realm`          |                             | makes `realm` optional |
| `kc-mcp.systems.<name>.*`       |                             | per system: `url`, `grant-type`, `client-auth`, `auth-realm`, `client-id`, `client-secret`, `username`, `password`, `default-realm`, `allowed-realms`, `version`, `issuer` |
| `kc-mcp.explanations`           | `auto`                      | refusal wording: `admins` (config details, `howToFix`), `users` (plain words), `auto` (by caller roles in delegation mode, else admins) |
| `kc-mcp.issuer`                 | `<url>/realms/<auth-realm>` | realm issuer as Keycloak states it, audience of `private_key_jwt` assertions; set when `kc-mcp.url` is internal (also per system, systems file) |
| `kc-mcp.version`                | read from server            | Keycloak version override / fallback ([Supported Keycloak versions](keycloak-versions.md)) |
| `kc-mcp.default-system`         | the only system             | system when `system` is omitted |
| `kc-mcp.allowed-hosts`          | any                         | `[scheme://]host[:port]` patterns with `*`, checked at startup |
| `kc-mcp.tool-prefix`            |                             | prefix for all tool names (`prod_`) |
| `kc-mcp.allowed-realms`         | all                         | csv allow-list |
| `kc-mcp.read-only`              | `false`                     | |
| `kc-mcp.allowed-tools` / `denied-tools` / `allowed-categories` | all | explicit narrowing |
| `kc-mcp.role-filter`            | `true`                      | hide/refuse tools the token's roles do not cover |
| `kc-mcp.startup-check`          | `warn`                      | `warn`, `fail`, `off` |
| `kc-mcp.tool-exposure`          | `hybrid`                    | `direct` / `lazy` / `hybrid` / `progressive` |
| `kc-mcp.hot-tools`              | user_search, user_get, realm_get_config, server_info | listed directly in hybrid mode |
| `kc-mcp.search-limit-default`   | `5`                         | hits per `search_tools` (max 10) |
| `kc-mcp.result-max-items`       | `100`                       | cap for list results |
| `kc-mcp.structured-content`     | `true`                      | mirror results as `structuredContent` |
| `kc-mcp.confirm-timeout-seconds`| `120`                       | elicitation timeout |
| `kc-mcp.config-files`           |                             | comma-separated properties files read at startup, between the built-in defaults and the environment; a later file overrides an earlier one (the distribution's `conf/kcmcp.properties`, then its `--config` files); a missing file stops the start; a path cannot contain a comma |
| `kc-mcp.providers-dir`          | `providers`                 | extension jars ([Extension jars](extending.md#extension-jars-providers)) |
| `kc-mcp.spi.<id>.<key>`         |                             | per extension; `enabled=false` disables; id kebab-case (`acmeTicketChecker` → `acme-ticket-checker`, env `KC_MCP_SPI_ACME_TICKET_CHECKER_*`, resolved by the server) |
| `quarkus.http.cors.origins`     | local origins               | browser MCP clients; set to the client origin(s) in production |
| `quarkus.otel.sdk.disabled`     | `true`                      | `false` exports metrics and traces to `quarkus.otel.exporter.otlp.endpoint` ([Metrics](metrics.md)) |
| `kc-mcp.metrics.include-realm` | `false`                    | tool call metrics carry the realm |
| `kc-mcp.ui.tls-configuration-name` |                        | named `quarkus.tls` configuration (trust store) for the server's own calls to the UI's identity providers: discovery, keys, session checks |
| `kc-mcp.http.connect-timeout` / `read-timeout` | `10s` / `60s` | outbound HTTP of the server's own clients (`10s`, `500ms`, `2m`, `PT1M`): CIBA, the UI's provider calls, and the read timeout of the Keycloak admin client (its connect timeout is the client's built-in 15 s); the read default leaves room for long admin calls such as a directory sync |
| `kc-mcp.ui.connect-timeout` / `read-timeout` | `kc-mcp.http.*` | the same for the UI's calls to its identity providers |

```properties
# service account with a secret (recommended)
kc-mcp.client-id=mcp-admin
kc-mcp.client-secret=...

# service account with private_key_jwt
kc-mcp.client-id=mcp-admin
kc-mcp.jwt.key-file=/etc/keycloak-mcp/mcp-admin.pem
# Keycloak: client mcp-admin -> Credentials -> "Signed JWT", "Use JWKS URL" on,
# JWKS URL = https://<this server>/.well-known/jwks.json (or import the key it prints);
# Client scopes -> add kc-admin-api as default (Keycloak 26.8.2+)

# local dev: admin user via admin-cli
kc-mcp.grant-type=password
kc-mcp.username=admin
kc-mcp.password=admin
```

Port 8081 (`quarkus.http.port`), endpoint `http://localhost:8081/mcp`. Service account roles: [Access levels](security.md#access-levels).
