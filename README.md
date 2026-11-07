# keycloak-mcp-server

[![CI](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml)

[MCP](https://modelcontextprotocol.io) server for Keycloak administration. Quarkus, `quarkus-mcp-server`, streamable
HTTP. 72 `keycloak_*` tools after [mcp-keycloak-admin](https://github.com/edewit/mcp-keycloak-admin), exposed lazily
so small local models cope.

Status: all reference tools, search, exposure modes, guardrails, extension SPI, database storage, admin API and the
management UI bootstrap (login, logout, BFF) done.
Open items: §Roadmap.

## How the model sees it

`tools/list` depends on `kc-mcp.tool-exposure`:

| mode          | `tools/list` contains |
|---------------|-----------------------|
| `hybrid`      | `search_tools`, `execute_tool`, hot tools (default) |
| `lazy`        | `search_tools`, `execute_tool` |
| `direct`      | every tool |
| `progressive` | hybrid + what the last `search_tools` surfaced, per connection (client must honour `tools/list_changed`) |

`whoami` is always listed.

- `search_tools(query, category?, limit?)`: lexical search over names, titles, descriptions, parameters and a synonym
  table ("kick" → logout, "ldap" → federation). Accents folded; German and French translated before matching
  (`search/QueryTranslations.java`, one table set per language); other languages: the instructions say search in English.
  Returns name, description, input schema. No arguments: lists categories. No match: the categories come along with a
  hint to pick one or tell the user the task is out of scope; a second miss on the same connection says stop, so a small
  model does not loop on rephrasing.
- `execute_tool(name, arguments, confirm?)`: same pipeline as direct calls: policy → validation/coercion → realm check →
  confirmation → handler → audit. Structured errors, always `isError: true`: `unknown_tool` (+ `didYouMean`),
  `invalid_arguments` (+ `problems`, schema), `realm_not_allowed`, `confirmation_required`, `read_only_mode`, `not_found`,
  `conflict`, `keycloak_unreachable`.
- `whoami(language?)`: who the session's Keycloak calls run as (signed-in user under `KC_MCP_DELEGATION=forward`, else
  the service account), `realm-management` roles per realm with admin-console labels (`language: de` → "Benutzer
  anzeigen"; others fall back to English, `labelLanguage` says so), per-area summary (`users: view`), tool count unlocked.
  With roles known, `search_tools` marks unusable hits `allowed: false` + `missingRoles`; `forbidden` errors point to `whoami`.
- Hidden tools stay callable by name.
- Forgiving identifiers: users by id or username, clients by id or clientId, groups by id, path or name. Strings coerced
  to booleans/integers; `max` clamped to `kc-mcp.result-max-items`.
- Every result twice: JSON text block + MCP `structuredContent` (lists as `{"items": [...]}`, errors with `error`).
  Off with `kc-mcp.structured-content=false`.
- Fewer round trips: membership and role changes return effective roles; `keycloak_user_roles_get` names each role's
  source (`direct`, `group:/path`, `composite:<role>`), default roles apart; `keycloak_group_get` shows what a group grants.

## Guardrails

- `KC_MCP_PROFILE=local|shared` (default `local`): the security defaults in one switch. `local` is one person's machine:
  anonymous endpoint behind DNS rebinding protection, `confirm: true` accepted, defaults fill in system and realm,
  outbound hosts unrestricted, storage encryption warned about. `shared` is a server other people reach: callers must
  authenticate (`quarkus.oidc.tenant-enabled=true` **and** `quarkus.oidc.token.audience`), destructive tools are
  confirmed through elicitation only (`kc-mcp.confirm-fallback=deny`), destructive tools name system and realm
  (`kc-mcp.explicit-target=destructive`), `kc-mcp.allowed-hosts` is required, an admin API issuer needs
  `kc-mcp.admin.audience`, the database storage needs `kc-mcp.storage.secret-key`. A missing setting stops the start
  with the full list. Each of the three defaults can still be set on its own in either profile.
- `KC_MCP_READ_ONLY=true`: hides and refuses WRITE/DESTRUCTIVE tools.
- `KC_MCP_ALLOWED_REALMS=a,b`: every call restricted; startup check verifies reachability (`kc-mcp.startup-check=warn|fail|off`).
- `KC_MCP_ALLOWED_HOSTS=*.example.com,localhost:8080`: every configured Keycloak URL (top level, per system) must match
  a `[scheme://]host[:port]` pattern, else no start.
- `kc-mcp.dynamic-private-hosts=allow|listed` (local `allow`, shared `listed`): a system registered at runtime (admin
  API, repositories) whose host resolves to a loopback, link-local, private or otherwise non-public address is refused
  (`private_host`) unless `kc-mcp.allowed-hosts` names the host literally, without a wildcard, so a registered URL
  cannot point the server at its own network. Static systems are the operator's choice and not checked. The admin
  client and the UI's discovery never follow redirects. The address is checked when the system is registered or
  changes, not again on every connection.
- `KC_MCP_ALLOWED_TOOLS`, `KC_MCP_DENIED_TOOLS`, `KC_MCP_ALLOWED_CATEGORIES`: explicit narrowing.
- DNS rebinding protection (`kc-mcp.dns-rebinding-protection`, default `auto`): while the MCP endpoint is anonymous,
  requests whose `Host` or `Origin` is not localhost answer 403 `forbidden_host`, so a web page cannot reach the local
  server through a name rebound to 127.0.0.1. Off once callers authenticate; `kc-mcp.dns-rebinding-allowed-hosts` adds
  `host[:port]` values for an anonymous server reached by name or through a proxy. JWKS and admin routes are not covered.
- Role filtering (`kc-mcp.role-filter`, default on). Tools declare roles (`ToolSpec.roles(...)`): `view-users` =
  `realm-management` client role, `my-app.auditor` = other client's role (split at last dot), `realm:support` = realm
  role. Implications as in Keycloak (`manage-x` ⊃ `view-x` ⊃ `query-x`, `realm-admin` ⊃ all). The server reads its own
  token, hides tools it lacks roles for, answers `forbidden` with the missing role on direct calls. Tokens without any
  admin role switch the filter off.
- DESTRUCTIVE tools (delete user/group, reset password, logout, unassign roles): MCP elicitation when the client supports
  it; without it `kc-mcp.confirm-fallback` decides: `flag` (local default) requires and explains `confirm: true`, `deny`
  (shared default) refuses with `confirmation_required` and does not offer the flag, since the model writes it. Own
  `Confirmer`s run first (§Extending), so a ticket check can still confirm under `deny`.
- CIBA confirmation (`kc-mcp.spi.ciba-confirmer.enabled=true`, off by default): the caller approves each destructive
  tool on their own device through OpenID Connect CIBA. The first call files the request and shows a two-digit
  number, the device shows who asks for what and asks for that number (number matching, as Entra ID), the next call
  runs the tool on approval, answers `cancelled` on a decline and `confirmation_required` while pending or after
  expiry. Neither the model nor the MCP client is in that channel. §Confirmers, `examples/ciba-confirm`.
- What the model is told about confirming (`kc-mcp.model-confirmation`, default `auto`): the server instructions say
  "never ask before calling", and `search_tools` hits of destructive tools, `whoami` and the `confirmation_required`
  answers carry the mode: `ask` (ask the user once after `confirmation_required`, then `confirm: true`), `server`
  (the server asks through the client's elicitation or on the user's device, or refuses: call right away and relay
  the answer). `auto` picks `server` whenever a confirmer asks the human itself (`Confirmer.asksTheHuman()`, the CIBA
  confirmer), the client supports elicitation, or `confirm: true` is not accepted; `ask` otherwise. Callers holding one
  of `kc-mcp.model-confirmation-trusted-roles` are told in `ask` mode to pass `confirm: true` right away. Guidance
  only, the confirmers enforce either way; it stops the "shall I really delete?" question where the device asks anyway.
- `kc-mcp.explicit-target=off|destructive|write` (local `off`, shared `destructive`): tools of that level get
  `system_required` / `realm_required` instead of the default system (when several exist) or default realm, so an
  ambiguous request cannot land on the default production system. A per-system entry (`/mcp/systems/<system>[/<realm>]`)
  counts as explicit.
- `keycloak_user_delete` also needs the matching `username`. `keycloak_realm_update` and `keycloak_auth_flow_bind` count
  as destructive (lock-out risk).
- One audit line per executed tool (`com.github.thomasdarimont.keycloak.mcp.audit`); `AuditListener` SPI gets the same
  event (tool, level, system, realm, redacted arguments, outcome, caller, client, duration).
- Sensitive values: arguments declared `.sensitive()` (JSON Schema `writeOnly`, `format: password`, so clients can mask
  them) and keys of map arguments declared `.sensitiveKeys(...)` never reach the audit log, the elicitation prompt or
  the CIBA device; undeclared names that end like a secret (`password`, `clientSecret`, `bindCredential`,
  `privateKey`, ...) are treated the same way at any depth of nested maps and lists, settings that only mention the
  word (`passwordPolicy`) are not. Error messages reach the audit with the values of sensitive arguments, bearer
  tokens, JWTs and `password=...` assignments taken out, at most 500 characters. Tools
  whose result is a secret (`keycloak_client_get_secret`, `..._regenerate_secret`) declare `.sensitiveResult()`: the
  caller still gets it, the audit line says `result=sensitive`. The MCP traffic log
  (`quarkus.mcp.server.traffic-logging.enabled`) writes everything verbatim; profile `shared` does not start with it.

## Access levels

The real boundary is the service account's roles in Keycloak. Server flags are a second layer.

| level          | Keycloak side | server side |
|----------------|---------------|-------------|
| full admin     | client in `master` with `admin`, or admin user via `admin-cli` | nothing |
| realm admin    | confidential client **in the realm** with `realm-admin` | `KC_MCP_ALLOWED_REALMS=<realm>`, `KC_MCP_DEFAULT_REALM=<realm>` |
| realm manager  | client in the realm with only the `realm-management` roles needed | as realm admin; role filtering hides the rest. Narrow further: `KC_MCP_DENIED_TOOLS=keycloak_user_delete`, `KC_MCP_READ_ONLY=true` |
| user (forward) | the human holds the roles; public PKCE client whose tokens carry the server's audience | `KC_MCP_DELEGATION=forward` + `QUARKUS_OIDC_TENANT_ENABLED=true`; no server credentials (§Callers) |
| delegated agent (exchange) | the human holds the roles and consents to the server's client acting for them (Keycloak 26.8 token exchange delegation, preview); the client's role scope caps every delegated token | `KC_MCP_DELEGATION=exchange` + the client's `client_credentials` + `QUARKUS_OIDC_TENANT_ENABLED=true` (§Callers, `examples/delegated-auth`) |

A `master` client may also manage realms via `<realm>-realm` client roles; the filter understands both.

Keycloak 26.8.2 and later check the audience of Admin REST API tokens: every client whose tokens reach the Admin API
(the service account client, the public client users log in with) needs the built-in `kc-admin-api` client scope,
default or optional. Without it every admin call answers `unauthorized`. The server requests that scope with every token
(`kc-mcp.admin-api-scope`), advertises it to MCP clients in the protected resource metadata, and asks again without it
when a Keycloak answers `invalid_scope`, so one configuration serves 26.8.1 and 26.8.2. The examples' realm and client
files carry the scope; a 26.8.1 import drops the unknown name silently. The startup log warns when the server's own
token lacks the audience on a 26.8.2+ server.

### Per-tool access checks and delegation

```java
tool("keycloak_user_delete")
    .roles("manage-users")
    .requiresFeatures("organization").minVersion("26.8")       // maxVersion("26") bounds it; §Supported Keycloak versions
    .access(ctx -> ctx.arg("username").startsWith("svc-")
            ? AccessCheck.Decision.deny("protected_user", "service users are deleted by the platform team")
            : AccessCheck.Decision.allow())
    .delegation(Delegation.ALLOWED)   // ALLOWED (default) | FORBIDDEN | REQUIRED
```

- `AccessCheck` gets tool, resolved realm, validated arguments, granted roles, `Caller`. Runs after realm and role
  checks, before confirmation. Denial: `{"error": <code>, "message": ...}`.
- Global checks: `ToolProvider.accessChecks(...)` or any CDI bean implementing `AccessCheck`.
- `Delegation`: with `KC_MCP_DELEGATION=forward` every call is delegated (`Caller.delegated()`): `FORBIDDEN` tools
  refused, `REQUIRED` tools usable; service account mode is the reverse. Default `FORBIDDEN`: `client_get_secret`,
  `client_regenerate_secret`, `realm_update`, `auth_flow_bind`, `federation_sync`.

### Built-in policies: group scope and no escalation

Provider `policies`, caller-relative, active once callers are authenticated (§Callers).

| `kc-mcp.spi.policies.*` | default | meaning |
|---|---|---|
| `group-scope` | `off` | `group`: callers manage only groups they belong to (or subgroups); `organization`: groups of their organizations |
| `manager-role` | | role needed for group management, e.g. `realm:group-manager` |
| `no-escalation` | `true` | grants (direct, client role, group mapping, membership) only within the caller's effective roles; no touching users who outrank them; no self-grants |
| `anonymous` | `allow` | `deny`: guarded tools refused without a known caller |
| `super-roles` | `realm:admin, realm-management.realm-admin` | holders bypass both checks |

Denials: `group_out_of_scope`, `manager_role_required`, `privilege_escalation`, `target_outranks_caller`, `self_grant`,
`caller_unknown`, `caller_foreign_realm`, `caller_required`. Effective roles come from Keycloak (direct, group, composite).

### Callers

`CallerProvider` reads the Quarkus `SecurityIdentity`: subject, username, issuing realm, roles. OIDC tenant off by
default (anonymous endpoint). `QUARKUS_OIDC_TENANT_ENABLED=true` verifies tokens of `KC_MCP_URL/realms/KC_MCP_AUTH_REALM`
(`quarkus.oidc.auth-server-url` to change, `QUARKUS_OIDC_TOKEN_AUDIENCE` to require an audience).

| | `KC_MCP_DELEGATION=off` (default) | `KC_MCP_DELEGATION=forward` | `KC_MCP_DELEGATION=exchange` |
|---|---|---|---|
| admin calls run as | service account | the caller's own token | a delegated token Keycloak exchanges the caller's for: `sub` the caller, `act` the server's client |
| roles that count | service account's (role filter) | caller's `realm-management` roles from their token, per call; Keycloak enforces again | the delegated token's: the caller's roles within the client's role scope; Keycloak enforces again |
| anonymous requests | allowed unless `KC_MCP_REQUIRE_CALLER=true` or `KC_MCP_PROFILE=shared` | `401` + `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"` | as forward |
| server credentials | required | optional (policies provider falls back to them for lookups) | the client's `client_credentials` (secret or `private_key_jwt`); no admin role on it |
| Keycloak side | | public client with an *Audience* mapper for the server | plus consent on that client, *Standard Token Exchange* on the server's client, an Admin Permissions `delegate` grant for it; Keycloak ≥ 26.8 with `--features=token-exchange-delegation,parameterized-scopes` (preview) |

- The `401` challenge drives OAuth-capable MCP clients (LM Studio, Claude): discover realm, browser login (code + PKCE), retry.
- Keycloak side: public client with an *Audience* mapper for the server (`examples/run-modes/realms/demo-realm.json`,
  `mcp-consumer`); `realm-management` roles on the humans, groups preferred.
- Audit line: `caller=alice(<sub>) delegated`.
- `exchange`: the MCP client must request the scope `delegation:client:<client id>` (advertised as `scopes_supported`
  in the protected resource metadata) and the user consents at login, every session. Without that the token has no
  `may_act` claim and every tool answers `delegation_failed` with what to do; `whoami` shows `delegation: {consented,
  actor}`. Keycloak's `TOKEN_EXCHANGE` event names the actor, its admin events the user. Walkthrough and the Keycloak
  setup: `examples/delegated-auth/`.
- `Caller`: `claims()`, `claim("department")`, `rawToken()`; `toString()` never prints the token; audit events get
  `withoutToken()`. Per-caller admin clients cached until token expiry.
- Token exchange (acting with narrowed, consented permissions): not implemented.

## Several Keycloak systems

`kc-mcp.systems.<name>.*`; every field falls back to the top-level value.

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

- More than one system: every tool gains a `system` argument (enum; optional with `kc-mcp.default-system`).
- Roles, allowed realms, default realm, startup checks, audit: per system.
- One `kc-mcp.jwt.key-file` serves all systems; without it each system gets its own key (§Dynamic systems).
- No `kc-mcp.systems.*`: one system `default`, no `system` argument.

### Dynamic systems and per-system keys

`KeycloakSystemRepository` extensions (`@AutoService` or CDI bean) supply systems at runtime: `names()`, `find(name)`.

- Off by default: `kc-mcp.dynamic-systems=true` enables repositories, `kc-mcp.spi.<id>.enabled` one of them. Found
  while off: only logged.
- The server creates nothing in Keycloak; the tenant registers the client, the server keeps its key.
- `CompositeKeycloakSystemRepository` asks repositories by `order()`. Static configuration sits at
  `kc-mcp.static-systems-order` (-1000): repositories cannot redefine configured systems unless that is raised. First
  repository knowing a name wins; admin client created on first use, cached per name; changed settings reconnect,
  forgotten systems drop.
- Schema of the `system` argument: a closed enum of the configured names without repositories; with one, a plain string
  (systems may appear at runtime), known names listed in the description as examples, unknown names answer `unknown_system`.
- `kc-mcp.allowed-hosts` still applies: outside systems are refused and logged, not fatal; so does
  `kc-mcp.dynamic-private-hosts` (§Guardrails).

Credentials by convention, no secret per tenant:

- Each system registers a confidential client (e.g. `keycloak-mcp-server`): service account, "Signed JWT", JWKS URL
  `https://<this server>/auth/keys/<system>/jwks.json`, the `realm-management` roles needed.
- The server signs with a key pair per system from a `KeyVault`, publishes the public half at that URL.
- Built-in vault: read-only PKCS#8 PEM files under `kc-mcp.keys-dir` (default `data/keys`, next to `quarkus-run.jar`
  when packaged): `<system>.pem`, secrets as `secrets/<name>` files.
- Own `KeyVault`: `findSigningKey`, `createSigningKey` when `supportsKeyCreation()`, `findSecret`, `putSecret` when
  `supportsSecretStorage()`. Keys generated by the `SigningKeyGenerator` the server hands over (JDK RSA/EC for
  `kc-mcp.jwt.algorithm`, RSA size `kc-mcp.jwt.key-size`; own one for an HSM). Or a secrets manager such as HashiCorp
  Vault: the server handles references only.
- `kc-mcp.jwt.key-file` keeps one key for all systems, also at `/.well-known/jwks.json`.
- `FileSystemKeycloakSystemRepository` reads `kc-mcp.systems-file` (re-read on change). `kc-mcp.static-systems=false`:
  repositories only. `examples/multi-tenant/`: two tenants, provisioned keys, one entry per tenant. Database: §Database storage.

```json
{ "systems": [
  { "name": "tenant-a", "url": "http://keycloak:8080", "authRealm": "tenant-a",
    "clientId": "keycloak-mcp-server", "clientAuth": "private_key_jwt",
    "defaultRealm": "tenant-a", "allowedRealms": ["tenant-a"] } ] }
```

### Admin API: registering systems at runtime

Needs database storage and `kc-mcp.admin.enabled=true`. JAX-RS under `/admin`. Full flow: `examples/dynamic-systems/`.

- Bearer: static `kc-mcp.admin.token`, or an access token of `kc-mcp.admin.issuer` (realm URL, verified by Quarkus OIDC,
  optional `kc-mcp.admin.audience`) carrying `kc-mcp.admin.role` (`realm:admin` default; `<client>.<role>` for client
  roles). One of token and issuer required.
- `PUT /admin/systems/<alias>`: systems file fields (`displayName`, `description`, `url`, `issuer`, `authRealm`,
  `clientId`, `clientAuth`, `defaultRealm`, `allowedRealms`, `version`, `clientSecret`) into the first
  `MutableKeycloakSystemRepository`. Registered systems are service clients: `client_credentials` with
  `private_key_jwt` or `client_secret`; `grantType: password` answers 400 `grant_not_supported`.
  `url` must pass `kc-mcp.allowed-hosts`. `kc-mcp.admin.allow-new-systems=false` freezes the set: unknown aliases answer
  403 `registration_closed`, known systems stay changeable (reading stored systems only needs `kc-mcp.dynamic-systems`,
  not the admin API).
- `signingKey`: `generate` (new pair in a creating vault), `existing` (vault already has one), absent (existing, else generate).
- `"clientSecret": "vault:<name>"`: checked on registration, resolved on every connection; rotating the secret needs no
  system change.
- Response: no secrets; `kid`, `jwksPath` (`/auth/keys/<alias>/jwks.json`), `jwksUrl`, entries, `createdAt` /
  `updatedAt` (ISO-8601, from repositories that keep them: the database, not the static configuration).
- `GET /admin/systems[/<alias>]`: all systems with `source` repository (configured ones read-only). `DELETE`: removes a
  registered system, keys stay. `POST /admin/systems/<alias>/signing-key`: rotates; JWKS lists the new key first, keeps
  the retired one for the grace period; Keycloak refetches on unknown `kid`.
- `PUT /admin/secrets/<name>` `{"value": "..."}`: stores a secret in the database vault (file vault, secrets manager:
  409 `vault_read_only`). Systems with `vault:<name>` pick it up on their next connection. `GET /admin/secrets[/<name>]`:
  names + `usedBy`, never values. `DELETE`: 409 `secret_in_use` while referenced.
- `GET /admin/storage`: encryption on/off, current key id, key ids in use per table. `POST /admin/storage/rekey`:
  re-encrypts under the current `kc-mcp.storage.secret-key` (§Database storage, key rotation).

### Database storage (optional)

Module `storage` (`keycloak-mcp-server-storage`, backend dependency).

- Stores: systems (`KeycloakSystemRepository` `db-systems`, `kc_mcp_system`), keys and secrets (`KeyVault` `db-key-vault`,
  `kc_mcp_signing_key`, `kc_mcp_secret`), audit (`AuditListener` `db-audit`, `kc_mcp_audit_event`, one row per call
  incl. denials and reads), browser sessions of the management UI (`UserSessionStore` `db-user-sessions`,
  `kc_mcp_user_session`, tokens encrypted, expired rows purged hourly).
- Hibernate ORM Panache; Liquibase at startup (`db/kc-mcp/changelog.xml` includes one file per schema version,
  `0.1.0-changelog.xml` first); timestamps `bigint` epoch millis as in Keycloak.
- Dormant without `quarkus.datasource.jdbc.url`. With one, `kc-mcp.storage.enabled` turns on (set explicitly to force);
  `kc-mcp.dynamic-systems=true` exposes stored systems, the database vault replaces the file vault, audit rows start.
  Per store: `kc-mcp.spi.db-systems.enabled`, `db-key-vault.enabled`, `db-audit.enabled`.

```shell
QUARKUS_DATASOURCE_JDBC_URL=jdbc:h2:file:./data/kc-mcp KC_MCP_DYNAMIC_SYSTEMS=true \
KC_MCP_STORAGE_SECRET_KEY=$(openssl rand -base64 32) java -jar modules/backend/target/quarkus-app/quarkus-run.jar
```

- Database kind is build time: default build embeds H2 (`jdbc:h2:file:...`, one instance); `./mvnw package -Ppostgresql`
  for PostgreSQL (`jdbc:postgresql://host:5432/kcmcp`, `quarkus.datasource.username`/`password`). Both drivers ship; the
  dialect does not switch at runtime.
- Share a database server with Keycloak, never its schema: tables are prefixed `kc_mcp_`.
- `kc-mcp.storage.secret-key` (base64 of 32 bytes, or a passphrase via Argon2id): AES-256-GCM for private keys, client
  secrets, passwords. Unset: plain text, startup warns. Values are `enc:v2:<key id>:<nonce>:<ciphertext>`; the key id
  (8 hex digits of the key's SHA-256) names the key they were written with.
- Key rotation: put the new key into `secret-key` and the old one into `previous-secret-keys` (decrypts only), roll
  out to every instance, let the startup pass or `POST /admin/storage/rekey` rewrite the rows (idempotent; plain and
  `enc:v1` values from older builds get encrypted too), check `GET /admin/storage` shows only the current key id, drop
  the old key. Rows under a key configured nowhere are reported as `remaining`, never touched.
- Pseudonyms are HMACs under `secret-key`, so a rotation changes them; `kc-mcp.spi.pii-audit-scrubber.pseudonym-key`
  gives the scrubber a key of its own.
- `kc_mcp_system`: `alias` = system name (`system` argument, `/mcp/systems/<alias>`), `name` = display label,
  `description` free text, UUID primary key; all changeable. `enabled=false`: kept, not served. Service clients only:
  no username/password columns, the repository refuses the password grant.
- Snapshot cache: rows reloaded when older than `kc-mcp.spi.db-systems.cache-seconds` (10; local writes reload at once).
  Tool calls cost no query; event-loop threads get the snapshot as is.
- Programmatic access: `DatabaseKeycloakSystemRepository` (`save`, `rename`, `setEnabled`, `delete`), `DatabaseKeyVault`
  (`createSigningKey` retires the previous row, `putSecret`), `DatabaseAuditListener` (`recent`, `byCaller`). Admin API
  over audit rows: next step.
- Retention: `kc-mcp.spi.db-audit.retention-days` deletes older events at startup and hourly (one statement on the
  `occurred_at` index). Unset keeps all, like Keycloak's event store without expiration.
- PII: `AuditScrubber` `pii-audit-scrubber`. `kc-mcp.spi.pii-audit-scrubber.pii`: `keep` (default), `pseudonymize`
  (caller name and `pii-args` values, default `username,email,firstName,lastName,search,userId,user,attributes` plus `id`
  on user tools, become a keyed hash under `secret-key`; message dropped), `drop`. `targets`: `db-audit` (default),
  `console`, `*`.

Several instances on one database (how `examples/dynamic-systems/` runs):

- PostgreSQL build (H2 file database is single-process); same `kc-mcp.storage.secret-key` everywhere.
- Systems: visible to other instances within `cache-seconds`. Secrets: next tool call. Signing keys: next token request
  of each instance; every JWKS publishes the current key plus keys retired within
  `kc-mcp.spi.db-key-vault.retired-key-grace-seconds` (3600), so Keycloak accepts lagging instances.
- Retention purge runs on every instance; deletes are idempotent.
- Two instances creating a first key at once: both succeed, both published, newest signs.

```java
@AutoService(KeycloakSystemRepository.class)
public class TenantRegistryRepository implements KeycloakSystemRepository {
    public String id() { return "tenant-registry"; }
    public List<String> names() { return registry.tenantIds(); }
    public Optional<KeycloakSystem> find(String name) {
        return registry.lookup(name).map(t -> KeycloakSystem.builder(name, t.keycloakUrl())
                .clientId("keycloak-mcp-server").defaultRealm(t.realm()).allowedRealm(t.realm()).build());
    }
}
```

Caller authentication is per MCP entry, not per system: one login per server URL. Several systems: one central identity
(master admin), or one entry per system (next section).

### Management UI (optional): `/ui`, BFF under `/bff`

Module `frontend` (`keycloak-mcp-server-frontend`, a Lit single-page app; the BFF is in the backend, package `ui`).
The server is the OIDC relying party: authorization code flow with PKCE, the browser holds an HttpOnly, Secure,
`SameSite=Lax` cookie with an opaque id, the tokens stay in the database (`kc_mcp_user_session`, encrypted like the
other secrets, `UserSessionStore` SPI, `db-user-sessions`). Needs database storage and HTTPS. Bootstrap:
`examples/management-ui/`, `modules/frontend/README.md`.

- `kc-mcp.ui.enabled=true`; `kc-mcp.ui.issuer` (default `kc-mcp.admin.issuer`, else the auth realm) and
  `kc-mcp.ui.client-id` (`keycloak-mcp-ui`: public, PKCE S256, redirect URI `<server>/bff/login`, post logout redirect
  URI `<server>/ui/*`; `kc-mcp.ui.client-secret` for a confidential client)
- Several identity providers: `kc-mcp.ui.idps.<alias>.issuer|client-id|client-secret|display-name`, one tenant
  `kc-mcp-ui-<alias>` and one sign-in button each (`/bff/login?idp=<alias>`); sessions record `idp` and `subject`
- `GET /bff/me` (who is signed in, the providers), `GET /bff/login[?idp=]`, `GET /bff/logout` (RP-initiated),
  `GET /bff/api/systems` (as `GET /admin/systems`); the API needs `kc-mcp.admin.role` on the access token, browser
  requests carry `X-Requested-With: JavaScript` (499 instead of a redirect without a session; required on writes)
- Nothing remembers a provider between sessions: a logout returns to `/ui/?idp=<alias>` and the page offers that
  provider first. `kc-mcp.ui.idps.<alias>.hide-on-login-page=true`
  keeps a provider off the login page, so a shared server does not advertise its tenants; its users sign in through
  `/bff/login?idp=<alias>`, and the UI names the provider once they are signed in
- Session check (activity tracking): `POST /bff/check-session`, which the UI calls whenever its tab becomes visible
  again, redeems the refresh token at the provider: proves the SSO session still exists and extends it, renews the
  stored tokens and the cookie; a session that ended elsewhere (account console, another application, an
  administrator, the idle timeout) answers 401 `session_ended` and loses its row, 503 when the provider cannot be asked
- Back-channel logout: `POST /bff/backchannel-logout` takes the provider's logout token (verified against the
  provider the token's `iss` and `aud` name) and deletes the sessions with that issuer and `sid` (or `sub`) at once,
  on every instance. Keycloak client: *Backchannel logout URL* = `<server>/bff/backchannel-logout`, *session required* on
- Sessions are renewed with the refresh token for `kc-mcp.ui.session-age-extension` (default 30 min, the provider's
  SSO idle timeout; per provider `kc-mcp.ui.idps.<alias>.session-age-extension`) past the ID token's expiry; rows
  carry `idp`, `issuer`, `subject`, `sid` and go when the tokens are of no use any more
- HTTPS: `etc/mkcert.sh` writes `.certs/localhost*.pem`; `QUARKUS_TLS_KEY_STORE_PEM_UI_CERT/KEY` point at them, port
  `quarkus.http.ssl-port=8443`; behind a TLS proxy `quarkus.http.proxy.proxy-address-forwarding=true`
- Several instances: set `QUARKUS_OIDC_KC_MCP_UI_<ALIAS>_AUTHENTICATION_STATE_SECRET` so any instance can finish a login
  another one started; the session rows are shared through the database
- Build: `./mvnw package` runs npm (Node downloaded once into `modules/frontend/node/`); `-Dui.skip=true` leaves the UI out

### Entries per system or realm: `/mcp/systems/<system>[/<realm>]`

Same server, bound to one system or realm.

- `system` and `realm` arguments filled from the entry; contradicting arguments: `entry_mismatch`.
- `search_tools` and `whoami` judge roles and capabilities against that system; `whoami` reports `entry`.
- Global tools ignore the realm part.
- With OIDC on, entry requests are verified against the system's auth realm (`<url>/realms/<auth-realm>`): tenant A's
  users log in at tenant A's Keycloak; forward delegation works across systems. Systems sharing the default tenant's
  realm keep the default tenant.
- Unknown system: `unknown_system` on every call. `/mcp/*` permission policy covers entries.

```json
{ "mcpServers": {
    "keycloak-prod":      { "url": "https://mcp.example.com/mcp/systems/prod" },
    "keycloak-customers": { "url": "https://mcp.example.com/mcp/systems/prod/customers" } } }
```

Support desk: realm entry. Operator: system entry or root.

One process per Keycloak instead: `kc-mcp.tool-prefix=prod_` renames tools (`prod_keycloak_user_search`);
`execute_tool` and config lists accept both spellings.

## Configuration

Property → environment variable: `kc-mcp.grant-type` → `KC_MCP_GRANT_TYPE`.

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
| `kc-mcp.profile`                | `local`                     | `local` or `shared`: defaults of the four rows below, and `shared` refuses to start without caller authentication + audience, `allowed-hosts`, admin audience, storage `secret-key` (§Guardrails) |
| `kc-mcp.require-caller`         | `false`, `shared`: always   | refuse anonymous requests with the OAuth challenge even with `delegation=off` |
| `kc-mcp.confirm-fallback`       | `flag`, `shared`: `deny`    | without elicitation: `flag` accepts `confirm: true`, `deny` refuses destructive tools |
| `kc-mcp.explicit-target`        | `off`, `shared`: `destructive` | `destructive` or `write` tools must pass `system` (several systems) and `realm` instead of the defaults |
| `kc-mcp.dynamic-private-hosts`  | `allow`, `shared`: `listed` | `listed`: a runtime-registered system on a private, loopback or link-local address needs its host named literally in `allowed-hosts` |
| `kc-mcp.model-confirmation`     | `auto`                      | guidance to the model about destructive tools: `ask`, `server`, `auto` (§Guardrails) |
| `kc-mcp.model-confirmation-trusted-roles` |                   | role refs whose holders are told to pass `confirm: true` right away in `ask` mode |
| `quarkus.oidc.tenant-enabled`   | `false`                     | verify bearer tokens; issuer `${kc-mcp.url}/realms/${kc-mcp.auth-realm}` |
| `quarkus.oidc.token.audience`   |                             | required `aud` (recommended with `forward`) |
| `quarkus.oidc.token.issuer`     |                             | public issuer when `kc-mcp.url` is internal (Docker) |
| `quarkus.oidc.resource-metadata.authorization-server` | `quarkus.oidc.auth-server-url` | login address MCP clients are sent to; the public issuer when `kc-mcp.url` is internal |
| `kc-mcp.default-realm`          |                             | makes `realm` optional |
| `kc-mcp.systems.<name>.*`       |                             | per system: `url`, `grant-type`, `client-auth`, `auth-realm`, `client-id`, `client-secret`, `username`, `password`, `default-realm`, `allowed-realms`, `version`, `issuer` |
| `kc-mcp.explanations`           | `auto`                      | refusal wording: `admins` (config details, `howToFix`), `users` (plain words), `auto` (by caller roles in delegation mode, else admins) |
| `kc-mcp.issuer`                 | `<url>/realms/<auth-realm>` | realm issuer as Keycloak states it, audience of `private_key_jwt` assertions; set when `kc-mcp.url` is internal (also per system, systems file) |
| `kc-mcp.version`                | read from server            | Keycloak version override / fallback (§Supported Keycloak versions) |
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
| `kc-mcp.providers-dir`          | `providers`                 | extension jars (§Extension jars) |
| `kc-mcp.spi.<id>.<key>`         |                             | per extension; `enabled=false` disables; id kebab-case (`acmeTicketChecker` → `acme-ticket-checker`, env `KC_MCP_SPI_ACME_TICKET_CHECKER_*`, resolved by the server) |
| `quarkus.http.cors.origins`     | local origins               | browser MCP clients; set to the client origin(s) in production |
| `quarkus.otel.sdk.disabled`     | `true`                      | `false` exports metrics and traces to `quarkus.otel.exporter.otlp.endpoint` (§Metrics) |
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

Port 8081 (`quarkus.http.port`), endpoint `http://localhost:8081/mcp`. Service account roles: §Access levels.

## Metrics (OpenTelemetry)

Off until asked for; then exported over OTLP to a collector (Prometheus, Grafana, Datadog ... behind it):

```shell
QUARKUS_OTEL_SDK_DISABLED=false
QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
# QUARKUS_OTEL_METRIC_EXPORT_INTERVAL=60s   QUARKUS_OTEL_TRACES_ENABLED=false (metrics only)
```

Quarkus reports HTTP server metrics per route (MCP endpoint, BFF, admin API), JVM metrics and a trace per request.
The server adds its own:

| metric | type | attributes | what it answers |
|---|---|---|---|
| `kc_mcp.tool.call.duration` | histogram, s (count = calls) | `tool`, `level`, `outcome` (`ok` or the error code), `via`, `system`, `realm` (opt-in) | is it used, is it working, what fails how |
| `kc_mcp.policy.refusals` | counter | `reason` (`forbidden`, `privilege_escalation`, `realm_not_allowed`, `read_only_mode`, `entry_mismatch`, ...), `tool`, `level`, `system` | misconfigured roles, or someone probing |
| `kc_mcp.confirmation.decisions` | counter | `confirmer` (`ciba-confirmer`, `built-in`, an extension's id, `none`), `outcome`, `tool` | who confirms destructive tools, how often they are declined |
| `kc_mcp.ciba.requests` | counter | `system` | approvals asked for |
| `kc_mcp.ciba.decisions`, `kc_mcp.ciba.decision.duration` | counter, histogram s | `outcome` (`approved`, `declined`, `expired`, `timeout`, `rejected`), `system` | how fast people answer; `rejected` = the approval's ID token was invalid or named someone else: alert on it |
| `kc_mcp.ciba.pending` | gauge | | approvals waiting for a device |
| `kc_mcp.discovery.searches` | counter | `result` (`hit`, `miss`, `stopped` by the repeated-miss brake), `mode`, `category` | how well models find tools |
| `kc_mcp.discovery.hits` | histogram | `mode` | tools per search |
| `kc_mcp.discovery.marked` | counter | `reason` (`forbidden`, `unsupported`) | hits shown with `allowed=false` |
| `kc_mcp.discovery.unknown_tools` | counter | `suggested` (`yes`/`no`: did-you-mean had candidates) | models guessing tool names |
| `kc_mcp.keycloak.request.duration` | histogram, s | `system`, `method`, `resource` (`users`, `groups`, `clients`, `realm`, ... never an id), `status_class` | Admin REST API latency and errors per system |
| `kc_mcp.keycloak.token.duration` | histogram, s | `system`, `grant` (`client_credentials`, `password`, `token-exchange`, `ciba`), `status_class` | token acquisition and delegation exchanges |
| `kc_mcp.keycloak.token.scope_fallbacks` | counter | `system` | servers that refused `kc-admin-api` |
| `kc_mcp.mcp.connections` | gauge | `client` (name from `initialize`, 20 distinct values, then `other`) | open MCP sessions |
| `kc_mcp.ui.sessions`, `kc_mcp.ui.backchannel_logouts` | gauge, counter (`result`: `ended`, `invalid`) | | management UI |

The Keycloak metrics come from a JAX-RS client filter on every RESTEasy client the server builds for a system (admin
client, `private_key_jwt` token manager, token exchange), since Quarkus does not instrument clients made outside CDI;
a request that gets no response at all is not measured there and shows up as `keycloak_unreachable` in the tool
calls. The CIBA client's requests to its provider are covered by `kc_mcp.ciba.*`.

No user, subject, argument or client-supplied value becomes an attribute; who did what is the audit log's. Values
are cut to short tokens, so an extension's odd error code cannot create unbounded series.
`kc-mcp.metrics.include-realm=true` adds the realm to the tool calls (one series per realm: think before turning
it on for a server with thousands). The tool and refusal metrics come from the audit hook (`AuditListener` id
`metrics`, `kc-mcp.spi.metrics.enabled=false` switches it off), so they count exactly what the audit log records.

## Extending

Depend on `com.github.thomasdarimont.keycloak:keycloak-mcp-server-api` (module `api`; Keycloak admin client and Vert.x
JSON, no Quarkus; automatic module `com.github.thomasdarimont.keycloak.mcp.api`). Packages under
`com.github.thomasdarimont.keycloak.mcp`:

- `spi`: `Extension`, `ExtensionRegistry`, `ExtensionContext`, `ProviderConfig`
- `tools`: `ToolProvider`, `ToolProviderContext`, `AbstractToolProvider`
- `prompts`: `PromptProvider`
- `access`: `AccessCheck`, `Caller`, `GrantedRoles`, `RoleRef`, `Delegation`
- `confirm`: `Confirmer`, `ConfirmationRequest`, `Decision`, `Prompter`
- `audit`: `AuditListener`, `AuditEvent`, `AuditScrubber`
- `catalog`: `ToolSpec`, `ToolCall`, `ToolResult`, `InputSchema`, `Category`, `ToolLevel`, prompt descriptions
- `keycloak`: `KeycloakAdmin`, `KeycloakSystems`, `KeycloakSystemRepository`, `KeyVault`, `SigningKeyGenerator`,
  capabilities, host allow list, `Views`
- `config`: server configuration interface, `Profile`, `ProfileCheck`

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

- Register: `@AutoService(ToolProvider.class)` (generates `META-INF/services/...tools.ToolProvider`), a hand-written
  services file, or a CDI bean.
- Secrets: `InputSchema.builder().string("pin", "...").sensitive()` for an argument, `.stringMap("config", "...")
  .sensitiveKeys("clientSecret")` for keys of a map, `ToolSpec.builder(...).sensitiveResult()` for a result that is a
  secret; `catalog.Sensitive` tells listeners and confirmers what to hide.
- Every tool declares its level, `.read()`, `.write()` or `.destructive()`; `build()` refuses a tool without one, so a
  forgotten call cannot slip past the read-only filter or the confirmation. The level is in every `search_tools` hit
  (`level`) and in the MCP tool annotations (`readOnlyHint`, `destructiveHint`).
- Provider tools get search, exposure modes, validation, realm checks, confirmation, audit.
- Built-in areas (`users`, `groups`, `roles`, `clients`, `idp`, `orgs`, `federation`, `auth-flows`, `events`, `realm`)
  use the same SPI; `kc-mcp.spi.<id>.enabled=false` switches one off.
- `Extension` base: `id()` (config key, kebab-case; default from class name, `com.acme.TicketChecker` →
  `com-acme-ticket-checker`), `displayName()`, `description()`, `order()` (lower first).
- `isSupported(serverConfig, config)` (default `true`): asked once at startup after `kc-mcp.spi.<id>.enabled`; an
  extension that needs a setting, a feature or a capability answers `false` when it is missing and is left out as if
  it were not installed (logged, not fatal; an exception counts as `false`). Applies to every extension point: tools,
  prompts, access checks, confirmers, audit listeners and scrubbers, profile checks, system repositories, key vaults,
  key generators, session and approval stores. Fail closed: `kc-mcp.spi.<id>.required=true` makes a missing,
  switched-off or unsupported extension stop the start (mark security controls such as an `AccessCheck` or a `Confirmer` this way),
  and an `isSupported` that throws stops a server in profile `shared`. Extension points are resolved at startup, so
  these rules apply before the first call. To refuse the start for other reasons, contribute a `ProfileCheck`. Built in:
  the CIBA confirmer is supported only with `kc-mcp.spi.ciba-confirmer.enabled=true`, the metrics audit listener only
  with the OpenTelemetry SDK on.
- `ExtensionRegistry` (`extensions(Confirmer.class)`, `extension(ToolProvider.class, "users")`, `context(id)`):
  discovery, dedup by id, enabled switch, order. CDI bean, injectable.
- Global `AccessCheck`: `@AutoService(AccessCheck.class)`, CDI bean, or `ToolProvider.accessChecks(...)`.

### Extension jars: `providers/`

- `kc-mcp.providers-dir` (`KC_MCP_PROVIDERS_DIR`), default `providers`. Every `ToolProvider`, `PromptProvider`,
  `AccessCheck`, `Confirmer`, `AuditListener`, `ProfileCheck` in the jars' `META-INF/services` joins the class path ones.
- Relative path: next to `quarkus-run.jar` when packaged (`target/quarkus-app/providers/`, created by the build), else
  the working directory (dev: `./providers`).
- Loaded by a class loader over the application: sees api and server classes, no CDI, no native image. CDI needed:
  Maven dependency instead.
- Docker image: `/deployments/providers` (`docker-compose.yml` has the volume line).

```shell
./mvnw package -DskipTests
cp acme-tools.jar modules/backend/target/quarkus-app/providers/
java -jar modules/backend/target/quarkus-app/quarkus-run.jar      # log: Extensions directory .../providers: [acme-tools.jar]
```

### Confirmers

- `Confirmer` (`@AutoService` or CDI bean, by `order()`) gets tool, realm, arguments, `confirm` flag, caller, a
  `Prompter` for elicitation.
- Returns `confirmed()`, `declined(message)`, `confirmationRequired(message)`, `abstain()`. First non-abstention wins;
  the built-in confirmer (elicitation, else `confirm` flag) runs last.

```java
@AutoService(Confirmer.class)
public class TicketConfirmer implements Confirmer {
    public Decision confirm(ConfirmationRequest r) {
        if (!r.tool().name().equals("keycloak_user_delete")) return Decision.abstain();
        String ticket = String.valueOf(r.args().get("ticket"));
        return tickets.isOpen(ticket) ? Decision.confirmed()
                : Decision.declined("User deletion needs an open change ticket (pass ticket=...).");
    }
}
```

#### Built-in: CIBA confirmation

`kc-mcp.spi.ciba-confirmer.*` (env `KC_MCP_SPI_CIBA_CONFIRMER_*`), off by default. With `enabled=true` the server
files a CIBA authentication request (OpenID Connect Client Initiated Backchannel Authentication) for the caller of
the MCP session before a DESTRUCTIVE tool runs: `login_hint` = the caller's username (or the claim named by
`login-hint`), `binding_message` = `<binding-message-prefix>-<hash of tool, system, realm, arguments>`, plus the
additional parameters `code` (a two-digit number), `requester` (the MCP client's name) and `operation` for the device
to show. Two-step flow (default): the first call answers `confirmation_required` at once with `approval: {status:
requested, code, bindingMessage, expiresInSeconds}` and a `howTo` telling the model to have the user approve on
their device and enter the number, then call again right away without waiting for a reply; the next call with the
same arguments waits up to `poll-wait-seconds` for the device, polling the token endpoint, so the decision is noticed
without the user writing in the chat. It runs the tool (`confirmed`), answers `cancelled` (declined), `confirmation_required` with `status: pending`
(still waiting, after `poll-wait-seconds`) or `status: expired` (nothing changed, call again for a new request).
Number matching as in Entra ID: the number is shown where the request originates and asked for where it is approved,
so a request the user did not trigger carries a number they cannot know. `flow=blocking` waits in the call instead,
without a number. Standard CIBA only, so any CIBA-capable provider works; the device side is the provider's
(Keycloak: its HTTP authentication channel, which forwards up to five additional parameters; see the example).

What makes the approval trustworthy:

- Bound to the full operation: the key is a SHA-256 over MCP session, caller, issuer and the SHA-256 of tool, system,
  realm and arguments, and the stored approval carries that hash, which the collecting call must match. Only the
  device's binding message shows a 40-bit prefix of it, for people to compare.
- One approval per session and operation, reserved atomically in the `PendingApprovalStore` with an opaque generation
  that every later change names: a late filer whose reservation expired cannot overwrite the next one, and an old
  generation cannot be consumed. One collector at a time holds a short claim and polls the provider; parallel calls
  answer pending without polling, and a decision is consumed once. The claim is renewed before every poll and lasts
  the read timeout plus a margin, so it cannot run out during a slow poll; an approval the provider confirmed is
  recorded for its generation before it is consumed, so a collector that stalls afterwards cannot lose it.
- No session, no two-step: a stateless MCP request (no `Mcp-Session-Id`) waits for the device within the call
  instead, since nothing would tie a second call to the first.
- Who approved is verified: the ID token the token endpoint returns on approval must verify against the provider's
  JWKS (signature, issuer, the CIBA client as audience, expiry), and its identity must be the person asked: the same
  `sub` as the MCP caller when their token comes from the same issuer, else the username or email of the login hint.
  Anything else answers `cancelled` with the reason and confirms nothing.
- Nothing falls back to the model: the confirmer refuses to start unless callers are required
  (`kc-mcp.require-caller`, a delegation mode or the shared profile), and an anonymous or unaddressable caller gets
  `confirmation_required`, never the default confirmer's `confirm: true`. The one deliberate hand-over is
  `when=without-elicitation`, to the client's elicitation.
- Pending approvals live in the database storage when it is on (`kc_mcp_pending_approval`, `db-approvals`, the
  `auth_req_id` encrypted under `secret-key`, purged hourly), so the collecting call may reach any instance; without
  the storage an in-memory store serves a single instance.

| `kc-mcp.spi.ciba-confirmer.*` | default | meaning |
|---|---|---|
| `enabled` | `false` | |
| `issuer` | `caller` | issuer URL of the CIBA client; `caller` follows the `iss` of the caller's token (the auth realm without one) |
| `token-issuer` | = `issuer` | the `iss` the provider's tokens carry when the server reaches it at an internal URL (Docker) |
| `tls-configuration-name` | | named `quarkus.tls.<name>.*` configuration whose trust store the calls to the provider use (private CA); unset: the JVM's default trust |
| `connect-timeout` / `read-timeout` | `kc-mcp.http.*` | timeouts of the calls to the provider (`10s`, `500ms`, ...) |
| `client-id` / `client-secret` | | the confidential client registered for CIBA (required when on) |
| `client-auth` | `client_secret_basic` | or `client_secret_post` |
| `scope` | `openid` | |
| `acr-values` | | optional, e.g. to demand a second factor on the device |
| `login-hint` | `username` | or a token claim (`email`, `sub`) the provider resolves the user by |
| `binding-message` / `binding-message-prefix` | `true` / `kc-mcp` | the message on the device; Keycloak allows 50 characters without spaces |
| `requested-expiry` | `false` | send `requested_expiry` = the timeout |
| `timeout-seconds` | `confirm-timeout-seconds` | how long to wait; capped by the provider's `expires_in` |
| `when` | `always` | `without-elicitation`: only for clients that cannot ask the human themselves |
| `flow` | `two-step` | or `blocking` (the call waits for the device; no number matching) |
| `number-matching` | `true` | two-step: send a two-digit `code` the device asks the user for; shown to the model |
| `extra-parameters` | `true` | send `requester` and `operation` as additional request parameters |
| `poll-wait-seconds` | `5` | two-step: how long the collecting call waits for the device before answering `pending` |

### Profile checks

`ProfileCheck` (`@AutoService` or CDI bean) adds to the startup checks of `kc-mcp.profile`: an extension states what
its own feature needs to be safe (an audit file outside `/tmp`, a ticket system over HTTPS, a setting that must not keep
its default on a shared server). `problems(ctx)` stop the start, reported together with the built-in ones and tagged
`[id]`; `warnings(ctx)` are logged. The check decides per profile (`ctx.shared()`), and gets its own settings
(`ctx.config()`, `kc-mcp.spi.<id>.*`), any property (`ctx.property("quarkus.http.host")`) and whether callers are
required. A check that throws stops a shared server and is logged on a local one. Example:
`examples/extensions/.../AuditFileProfileCheck.java`.

```java
@AutoService(ProfileCheck.class)
public class TicketUrlCheck implements ProfileCheck {
    public List<String> problems(ProfileCheckContext ctx) {
        String url = ctx.config().get("url", "");
        return ctx.shared() && !url.startsWith("https://")
                ? List.of("kc-mcp.spi." + id() + ".url must be https on a shared server") : List.of();
    }
}
```

### Audit listeners and scrubbers

- `AuditListener.onToolCall` once per finished call, any outcome. Built-in: console line (`console`). Synchronous on the
  handler's virtual thread; offload slow sinks. Exceptions logged, never change the result.
- Password-like arguments arrive as `***`. Personal data does not: that is `AuditScrubber` (`@AutoService` or CDI bean,
  by `order()`). `scrub(event, listener)` runs per listener: treat all sinks alike, or target one by id (`db-audit`,
  `console`). Derive with `mapArgs`, `withMessage`, `withCaller`; return `null` to skip. Default `NoOpAuditScrubber`.

```java
@AutoService(AuditListener.class)
public class SiemAuditListener implements AuditListener {
    public void onToolCall(AuditEvent e) {
        if (!e.succeeded() || e.level() != ToolLevel.READ) {
            siem.send(e.tool(), e.realm(), e.caller().name(), e.outcome(), e.args());
        }
    }
}

@AutoService(AuditScrubber.class)
public class NoEmailScrubber implements AuditScrubber {        // no e-mail addresses in any audit sink
    public AuditEvent scrub(AuditEvent e, AuditListener target) {
        return e.mapArgs(k -> k.equals("email"), v -> "***");
    }
}
```

## Prompts

`prompts/list` offers recipes (`PromptSpec` from `PromptProvider`s).

- A prompt names its tools; the rendered text ends with their names, levels, descriptions, parameters: no
  `search_tools` round trip. `progressive` mode surfaces them in `tools/list`.
- Disabled tools (read-only, denied) drop out; a prompt without tools is not registered.

| prompt | arguments | does |
|---|---|---|
| `keycloak_onboard_user` | `username`, `email`, `realm?`, `firstName?`, `lastName?`, `groups?`, `actions?` | duplicate check, create, groups, setup email, verification |
| `keycloak_login_troubleshoot` | `username`, `realm?`, `client?` | read-only: account state, failed logins, brute force, realm/client settings, proposed fix |

```java
@AutoService(PromptProvider.class)
public class AcmePrompts implements PromptProvider {
    public String id() { return "acme-prompts"; }
    public List<PromptSpec> prompts(ToolProviderContext ctx) {
        return List.of(PromptSpec.builder("acme_offboard_user")
                .title("Offboard a user").description("Disable, log out and remove from groups.")
                .required("username", "Who leaves")
                .tools("keycloak_user_set_enabled", "keycloak_user_logout", "keycloak_user_groups_list", "keycloak_group_member_remove")
                .handler(a -> "Offboard " + a.get("username") + ": disable the account, end sessions, leave all groups, report.")
                .build());
    }
}
```

## Supported Keycloak versions

Baseline **Keycloak 26.8** (OpenAPI alignment, integration tests). Newer expected to work; older unchecked. Since
26.8.2 the Admin API requires the `kc-admin-api` client scope on the calling client (§Access levels).

- At startup and every ten minutes: version and enabled features per system from the admin server info (server
  credentials), kept as a capability snapshot. `kc-mcp.version` / `kc-mcp.systems.<name>.version` override and fill in;
  mismatch logged.
- Tool requirements: `requiresFeatures("organization", ...)` (CLI feature names), `minVersion("26.9")`,
  `maxVersion("26")` (inclusive at the given precision; above it the refusal says "removed"). Organization tools carry
  the feature requirement.
- Unmet requirements explain, never hide:
  - `search_tools`: `allowed=false`, reason `unsupported`
  - call: error `unsupported` + `howToFix` per deployment form (`KC_FEATURE_ORGANIZATION=enabled`,
    `kc.sh start --feature-organization=enabled`, `keycloak.conf`, container, Operator CR, `--features=`), restart note,
    `keycloak_server_features` to verify, <https://www.keycloak.org/server/features>
  - `whoami`: `server` version, baseline, `unavailableTools` by reason, `howToFix`; `keycloak_server_features`:
    `howToEnable` / `howToDisable`
  - startup check: logs version and unavailable tools; below baseline is a problem (`fail` aborts)
- Wording by `kc-mcp.explanations`: `admins` technical + `howToFix`; `users` plain ("the 'organization' feature is
  switched off. A Keycloak administrator can enable it") with a hint to keep it plain; `auto` picks `users` for forward
  callers without master admin or `realm-admin`, else `admins`. Support desk: `KC_MCP_EXPLANATIONS=users`.
- Unknown capabilities never block; Keycloak decides.
- Version differences under one endpoint live in the handler (`call.capabilities()`: `atLeast("26.9")`,
  `hasFeature(...)`), one schema with optional version-specific parameters. Never two `ToolSpec`s with one name: the
  tool list must not depend on the target system.

## Keeping the tools aligned with a Keycloak version

- Every tool declares its Admin REST operations (`ToolSpec.api(...)`, `ApiOperation`): method, path, argument → path/query
  parameter, body fields written.
- `OpenApiAlignmentTest` checks against `src/test/resources/openapi/keycloak-<version>.json` (26.8.2 checked in):
  operation exists, not deprecated, parameters and body fields exist with compatible types/enums. Unexposed spec
  parameters: drift report.
- Server info and user storage sync are missing from the published document: marked `unspecified` with a reason.
- The Java admin client is versioned independently since Keycloak 26.1; this test plus Testcontainers tie the tool
  surface to a server version.

```shell
curl -o src/test/resources/openapi/keycloak-26.9.0.json https://www.keycloak.org/docs-api/26.9.0/rest-api/openapi.json
./mvnw test -Dtest=OpenApiAlignmentTest -Dsurefire.failIfNoSpecifiedTests=false -Dkeycloak.openapi.version=26.9.0
```

## Examples

- `examples/run-modes/`: one Keycloak, demo realm, one env file per run mode (full admin, realm admin, read-only,
  `private_key_jwt`, several systems, forward delegation, the `shared` profile); IntelliJ run configurations.
- `examples/multi-tenant/`: two tenants, several realms, systems from a file, generated per-tenant keys, one entry per
  tenant or realm, second server with user login per realm.
- `examples/dynamic-systems/`: no system at startup; registration via admin API into PostgreSQL with a generated key,
  Keycloak client with its JWKS URL, realm with public `mcp-consumer`, admin/support/developer users.
- `examples/extensions/`: an extension jar for `providers/`: tools, prompt, confirmer, global access check, audit
  listener, scrubber, system repository, with unit tests against the api alone.
- `examples/management-ui/`: the management UI on the run-modes stack: mkcert certificate, one or two identity
  providers, alice (admin) and carol (forbidden), the Vite dev server
- `examples/delegated-auth/`: the server as a delegated agent (`KC_MCP_DELEGATION=exchange`): Keycloak 26.8 with
  token exchange delegation, consent, Admin Permissions grant, an actor client whose role scope caps every delegated
  token, a scripted browser login and the audit trail on both sides.
- `examples/ciba-confirm/`: destructive tools approved on the user's device through CIBA: Keycloak with the CIBA grant
  and its HTTP authentication channel, an "approver" app standing in for the device (an OpenID Connect relying party
  where the user signs in, sees the requests meant for them and enters the number from the chat),
  `confirm-fallback=deny`, a scripted approve / decline / wrong-user / ignored-flag run.

## Running

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

LM Studio `mcp.json`; with OIDC on add `"auth": { "CLIENT_ID": "mcp-consumer" }` (`examples/run-modes/mcp-oauth.json`):

```json
{ "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp" } } }
```

## Tool areas

| category        | tools |
|-----------------|-------|
| users, sessions | search, get, create, update, set_enabled, delete, reset_password, send_action_email, sessions_list, logout |
| groups          | list (search matches subgroups), get (granted roles incl. inherited), create, delete, members_list, member_add, member_remove, user_groups_list, role_assign |
| roles           | role_list, client_roles_list, user_roles_get (direct + effective realm and client roles, groups, source per role), user_role_assign/unassign, user_client_roles_get, user_client_role_assign/unassign |
| clients, scopes | list, get, get_secret, regenerate_secret, create, update (incl. `attributes`: ACR/LoA, logout URIs, lifespans), delete, mappers_list, scopes_list, default_scopes_get, scope_assign/unassign, example_token (access/ID token, userinfo or SAML response, like the console's *Evaluate*), evaluate_scopes, authz_resources_list, authz_policies_list, authz_permissions_list |
| idp             | list, get, mappers_list, create, delete |
| orgs            | list, get, create, delete, idp_list, idp_link, idp_unlink |
| federation      | list, get, sync |
| auth flows      | flows_list, executions_list, authenticator_providers_list, flow_create/copy/bind, execution_add/update/raise/lower/delete, execution_config_get/set (provider setting names and help), subflow_add, required_actions_list, required_action_set_enabled |
| events          | events_login, events_admin |
| realm           | server_info (version per system), server_features (all flags, or one by name), realm_get_config, realm_update |

## Roadmap

- Model-in-the-loop benchmarks with LM Studio: turns to success, tool-choice errors, tokens per mode
- Reference skill recipes as prompts
- Federation sync test against a real LDAP
- `private_key_jwt` against a JWT-authenticated Keycloak client
- Admin API read access to audit rows and signing-key history

## Quarkus notes

Dev UI <http://localhost:8081/q/dev/>. Native: `./mvnw package -Dnative` (untested).
