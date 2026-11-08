# Database storage

[keycloak-mcp-server](../README.md) › documentation

The optional `storage` module (`keycloak-mcp-server-storage`, a dependency of the backend) keeps what the server would
otherwise hold in files or memory in a database: systems, keys and secrets, audit events, UI sessions and pending
approvals. With it, several instances share one state. Without a JDBC URL it stays dormant.

## What is stored

| store | SPI id | table | holds |
|---|---|---|---|
| systems | `db-systems` (`KeycloakSystemRepository`) | `kc_mcp_system` | Keycloak systems registered at runtime |
| keys and secrets | `db-key-vault` (`KeyVault`) | `kc_mcp_signing_key`, `kc_mcp_secret` | per-system signing keys, client secrets |
| audit | `db-audit` (`AuditListener`) | `kc_mcp_audit_event` | one row per call, denials and reads included |
| UI sessions | `db-user-sessions` (`UserSessionStore`) | `kc_mcp_user_session` | the management UI's sessions, tokens encrypted, expired rows purged hourly |
| pending approvals | `db-approvals` (`PendingApprovalStore`) | `kc_mcp_pending_approval` | CIBA requests waiting for a device ([CIBA confirmation](ciba-confirmation.md)) |

Hibernate ORM with Panache; Liquibase creates and migrates the schema at startup (`db/kc-mcp/changelog.xml` includes
one file per schema version, `0.1.0-changelog.xml` first). Timestamps are `bigint` epoch milliseconds, as in Keycloak.

## Turning it on

A `quarkus.datasource.jdbc.url` switches the storage on (`kc-mcp.storage.enabled` forces it on or off). Then
`kc-mcp.dynamic-systems=true` exposes the stored systems, the database vault replaces the file vault, and audit rows
start. Each store has its own switch: `kc-mcp.spi.db-systems.enabled`, `db-key-vault.enabled`, `db-audit.enabled`.

```shell
QUARKUS_DATASOURCE_JDBC_URL=jdbc:h2:file:./data/kc-mcp KC_MCP_DYNAMIC_SYSTEMS=true \
KC_MCP_STORAGE_SECRET_KEY=$(openssl rand -base64 32) java -jar modules/backend/target/quarkus-app/quarkus-run.jar
```

- **The database kind is fixed at build time.** The default build embeds H2 (`jdbc:h2:file:...`, a single instance);
  `./mvnw package -Ppostgresql` builds for PostgreSQL (`jdbc:postgresql://host:5432/kcmcp` with
  `quarkus.datasource.username` and `password`). Both drivers ship, but the dialect does not switch at runtime.
- **Share a database server with Keycloak, never its schema.** The tables are prefixed `kc_mcp_`.

## Encryption and key rotation

`kc-mcp.storage.secret-key` encrypts private keys, client secrets and passwords with AES-256-GCM. It is the base64 of
32 bytes, or a passphrase that Argon2id turns into one. Unset, the values are stored in plain text and the startup log
warns; the `shared` profile refuses to start without it. Stored values read `enc:v2:<key id>:<nonce>:<ciphertext>`;
the key id, 8 hex digits of the key's SHA-256, names the key they were written with.

Rotating the key:

1. Put the new key into `secret-key` and the old one into `previous-secret-keys` (comma separated; they only decrypt).
2. Roll that out to every instance.
3. Let the startup pass rewrite the rows, or call `POST /admin/storage/rekey`. Both are idempotent, and plain and
   `enc:v1` values from older builds get encrypted as well.
4. Check that `GET /admin/storage` shows only the current key id in use.
5. Drop the old key from `previous-secret-keys`.

Rows written under a key that is configured nowhere are reported as `remaining` and never touched.

Audit pseudonyms are HMACs under `secret-key`, so a rotation changes them. `kc-mcp.spi.pii-audit-scrubber.pseudonym-key`
gives the scrubber a key of its own that rotates independently.

## Systems in the database

`kc_mcp_system` has a UUID primary key and holds `alias` (the system name: the `system` argument,
`/mcp/systems/<alias>`), `name` (a display label) and `description`; all three can change. `enabled=false` keeps a
system but stops serving it. Only service clients are stored: there are no username and password columns, and the
repository refuses the password grant.

Reads are served from a snapshot, reloaded when older than `kc-mcp.spi.db-systems.cache-seconds` (10; a local write
reloads at once). A tool call costs no query, and event-loop threads get the snapshot as is.

## Audit retention and personal data

- **Retention.** `kc-mcp.spi.db-audit.retention-days` deletes older events at startup and then hourly, one statement on
  the `occurred_at` index. Unset keeps everything, like Keycloak's event store without expiration.
- **Personal data.** The `pii-audit-scrubber`, an `AuditScrubber`, decides what of it reaches the rows (`kc-mcp.spi.pii-audit-scrubber.pii`):
  `keep` (default); `pseudonymize`, which turns the caller name and the values of the `pii-args` arguments
  (`username,email,firstName,lastName,search,userId,user,attributes`, plus `id` on user tools) into a keyed hash under
  `secret-key` and drops the message; or `drop`. `targets` names the listeners it applies to: `db-audit` (default),
  `console`, or `*`.

## Several instances on one database

This is how `examples/dynamic-systems/` runs. It needs the PostgreSQL build (the H2 file database is single-process)
and the same `kc-mcp.storage.secret-key` on every instance.

| change on one instance | visible on the others |
|---|---|
| a system registered, changed or removed | within `cache-seconds` |
| a secret stored | on their next tool call |
| a signing key rotated | on their next token request; every JWKS publishes the current key plus keys retired within `kc-mcp.spi.db-key-vault.retired-key-grace-seconds` (3600), so Keycloak accepts a lagging instance |
| an audit retention purge | runs on every instance; deletes are idempotent |

Two instances creating a first signing key at the same time both succeed: both keys are published, the newest signs.

**MCP sessions and several instances.** The streamable HTTP transport keeps a session (the `Mcp-Session-Id` the
`initialize` answer hands out) in the memory of the instance that opened it: the MCP server extension's
`ConnectionManager` is a map, deliberately without a store behind it (the upstream request for one, quarkiverse issue
510, was closed in favour of the protocol's stateless mode). The session holds little: the protocol version, the client's
capabilities (whether it supports elicitation, which the confirmation of destructive tools relies on), an open SSE stream
and, in the `progressive` tool exposure only, the tools the last `search_tools` surfaced. Everything a request needs is
taken from the request itself (the caller from the token, system and realm from the entry) or from the database
(systems, keys, secrets, pending approvals, UI logins, the audit trail), so losing a session loses nothing the user did.

- **Clients speaking MCP 2026-07-28 or later** run stateless: no session, a transient connection per request with the
  client's capabilities in the request's `_meta`. Any instance serves any request; nothing to configure.
- **Older clients** (2025-11-25 and before, most clients in the field) hold a session. A request that reaches an
  instance which does not know its session answers 404, and the MCP specification has the client start over with a new
  `initialize` on that answer: a failover, or plain round-robin routing, costs the client one re-initialization and is
  invisible to the user. Sticky routing on the `Mcp-Session-Id` header (a hash of it, or a header-based affinity rule)
  spares even that and keeps SSE streams on the instance that serves them; use it where the load balancer offers it.
- **`quarkus.mcp.server.http.streamable.auto-init=true`** makes every instance accept any request from an older client
  by opening a session on the spot, honouring capabilities the client puts into `_meta` and assuming none otherwise. The
  extension documents it as a stop-gap until every client speaks the stateless protocol; without the capabilities the
  server cannot tell whether a client supports elicitation, so on a shared server prefer sticky routing and leave it off.

## From code

`DatabaseKeycloakSystemRepository` (`save`, `rename`, `setEnabled`, `delete`), `DatabaseKeyVault` (`createSigningKey`
retires the previous row, `putSecret`) and `DatabaseAuditListener` (`recent`, `byCaller`) are injectable. An admin API
over the audit rows is on the roadmap.
