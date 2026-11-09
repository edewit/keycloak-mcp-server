# Extending

[keycloak-mcp-server](../README.md) › documentation

The extension SPI of the `api` module: tools, prompts, access checks, confirmers, profile checks, audit listeners and scrubbers, system repositories and key vaults; how extension jars are loaded. Worked example: `examples/extensions/`.

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
- `configure(config)` (default nothing): hands every extension its `kc-mcp.spi.<id>.*` settings, from files,
  environment and command line, at startup after the `enabled` switch and before `isSupported`. Keep them in fields;
  a constructor cannot see them. Only the settings are passed, the Keycloak systems do not exist yet; tool providers
  also get `init(ctx)` with the full context. A failing `configure` counts like a failing `isSupported`.
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
- `close()` (default nothing): once at shutdown for every extension that took part, last admitted first; a failure is
  logged and the others still close. Release connections, file handles and threads here.
- Lifecycle: one instance per server, shared by all requests, so an extension must be thread-safe. Each extension
  point is discovered once. `configure` and `isSupported` run once at startup, and settings need a restart to change.
- `ExtensionRegistry` (`extensions(Confirmer.class)`, `extension(ToolProvider.class, "users")`, `context(id)`):
  discovery, dedup by id, enabled switch, order. CDI bean, injectable.
- Global `AccessCheck`: `@AutoService(AccessCheck.class)`, CDI bean, or `ToolProvider.accessChecks(...)`.

## Extension jars: `providers/`

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

## Confirmers

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

## Built-in: CIBA confirmation

The built-in confirmer that has the caller approve each destructive tool on their own device through OpenID Connect
CIBA has a page of its own: [CIBA confirmation](ciba-confirmation.md). `examples/ciba-confirm` runs it.

## Caller issuer policies

In delegation mode a caller's token is used at the Keycloak system a call targets. The built-in rule lets it reach
the Keycloak that issued it (any realm of it, compared by the issuer's base), plus the
`kc-mcp.systems.<name>.trusted-issuers`: an entry with a realm path (`https://sso.example/realms/demo`) is that one
issuer, an entry without (`https://sso.example`) every realm of that Keycloak. Everything else answers
`caller_foreign_system`. A `CallerIssuerPolicy` (`@AutoService` or CDI bean, by `order()`) decides
before that rule: `ALLOW`, `DENY`, or `ABSTAIN` to leave it to the next one; the built-in rule runs last and never
abstains. A policy that throws counts as a denial.

```java
@AutoService(CallerIssuerPolicy.class)
public class FederationPolicy implements CallerIssuerPolicy {
    public Decision decide(String issuer, KeycloakSystem system) {
        return federation.trusts(system.name(), issuer) ? Decision.ALLOW : Decision.ABSTAIN;
    }
}
```

A policy decides what the server may send, nothing more: allowing a foreign issuer does not make the target Keycloak
accept its tokens. That is configured in Keycloak, where 26.5 introduced the JWT authorization grant (RFC 7523,
preview) for exactly this, an identity provider that lets a client present the external token as `assertion` and get
a local one, as the standard replacement for the external-to-internal token exchange
(<https://www.keycloak.org/2026/01/jwt-authorization-grant>). The server does not perform that grant yet: in mode
`forward` an allowed foreign token is sent as it is, and Keycloak refuses it unless configured to take it.

## Profile checks

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

## Audit listeners and scrubbers

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
