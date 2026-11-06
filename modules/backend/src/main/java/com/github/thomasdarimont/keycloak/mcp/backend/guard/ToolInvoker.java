package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ArgumentValidator;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

/**
 * The single execution path for every tool, whether called directly or through
 * {@code execute_tool}: policy -> validation -> realm -> confirmation -> handler ->
 * audit. In the delegation modes the caller's token ({@code forward}), or the delegated
 * token exchanged for it ({@code exchange}), replaces the server's credentials for the
 * handler and the role checks.
 */
@ApplicationScoped
public class ToolInvoker {

    private static final Logger LOG = Logger.getLogger(ToolInvoker.class);

    private final ToolCatalog catalog;
    private final AccessPolicy policy;
    private final Confirmer confirmer;
    private final int maxItems;
    private final KeycloakSystems systems;
    private final DelegationMode delegation;
    private final AuditLog audit;

    private Duration confirmTimeout = Duration.ofSeconds(120);
    private ExplicitTarget explicitTarget = ExplicitTarget.OFF;
    private ConfirmFallback confirmFallback = ConfirmFallback.FLAG;

    @Inject
    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, ConfirmerChain confirmer, McpServerConfig config,
            KeycloakSystems systems, AuditLog audit) {
        this(catalog, policy, confirmer, config.resultMaxItems(), systems, config.delegation(), audit);
        this.confirmTimeout = Duration.ofSeconds(config.confirmTimeoutSeconds());
        this.explicitTarget = config.effectiveExplicitTarget();
        this.confirmFallback = config.effectiveConfirmFallback();
    }

    /**
     * Which tools must name system and realm instead of taking the defaults
     * ({@code kc-mcp.explicit-target}).
     */
    public ToolInvoker explicitTarget(ExplicitTarget explicitTarget) {
        this.explicitTarget = explicitTarget == null ? ExplicitTarget.OFF : explicitTarget;
        return this;
    }

    public ExplicitTarget explicitTarget() {
        return explicitTarget;
    }

    /**
     * Whether {@code confirm: true} counts, decides the hint of
     * {@code confirmation_required}.
     */
    public ToolInvoker confirmFallback(ConfirmFallback confirmFallback) {
        this.confirmFallback = confirmFallback == null ? ConfirmFallback.FLAG : confirmFallback;
        return this;
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems) {
        this(catalog, policy, confirmer, maxItems, null, DelegationMode.OFF);
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems) {
        this(catalog, policy, confirmer, maxItems, systems, DelegationMode.OFF);
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems, DelegationMode delegation) {
        this(catalog, policy, confirmer, maxItems, systems, delegation, new AuditLog(List.of(AuditLog.LOG_LINE)));
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems, DelegationMode delegation, AuditLog audit) {
        this.catalog = catalog;
        this.policy = policy;
        this.confirmer = confirmer;
        this.maxItems = maxItems;
        this.systems = systems;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
        this.audit = audit;
    }

    public ToolResult invoke(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag, InvocationContext ctx) {
        long start = System.nanoTime();
        ToolResult result;
        String realm = null;
        String system = null;
        try {
            if (delegation.delegating() && ctx.callerToken() == null) {
                result = ToolResult.error("caller_required", "This server runs every Keycloak call on behalf of the "
                        + "caller; connect through an authenticated (OAuth) MCP session first.");
            }
            else if (delegation.delegating() && !ctx.caller().delegated()) {
                return invoke(spec, rawArgs, confirmFlag, ctx.withCaller(ctx.caller().asDelegated()));
            }
            else if (!policy.permits(spec)) {
                result = policy.forbids(spec, null).orElseThrow();
            }
            else {
                EntryBinding binding = ctx.binding();
                ToolResult bindingError = binding == null ? null : bindingMismatch(spec, rawArgs, binding);
                ArgumentValidator.Outcome outcome = ArgumentValidator.validate(spec.inputSchema(),
                        binding == null ? rawArgs : withBinding(spec, rawArgs, binding));
                if (bindingError != null) {
                    result = bindingError;
                }
                else if (!outcome.valid()) {
                    result = ToolResult.error("invalid_arguments", "Arguments do not match the tool schema.",
                            "problems", outcome.problems().stream().map(ArgumentValidator.Problem::toMap).toList(),
                            "inputSchema", spec.inputSchema().getMap());
                }
                else {
                    Map<String, Object> args = outcome.values();
                    KeycloakAdmin admin = null;
                    ToolResult systemError = null;
                    String requested = binding != null ? binding.system() : (String) args.get(InputSchema.SYSTEM);
                    boolean explicit = explicitTarget.appliesTo(spec.level());
                    if (systems != null) {
                        system = requested != null ? requested : systems.defaultName().orElse(null);
                        if (system == null) {
                            systemError = ToolResult.error("system_required", "Pass the system argument.", "systems",
                                    systems.names());
                        }
                        else if (requested == null && explicit && systems.names().size() > 1) {
                            systemError = ToolResult.error("system_required",
                                    "This server does not apply the default" + " system to "
                                            + spec.level().name().toLowerCase() + " tools (kc-mcp.explicit-target="
                                            + explicitTarget.name().toLowerCase() + "): pass the system argument.",
                                    "systems", systems.names(), "defaultSystem", system);
                        }
                        else if (systems.find(system).isEmpty()) {
                            systemError = ToolResult.error("unknown_system",
                                    "No Keycloak system named '" + system + "'.", "systems", systems.names());
                        }
                        else {
                            admin = systems.get(system);
                            if (delegation.delegating()) {
                                admin = admin.forToken(ctx.callerToken());
                            }
                        }
                    }
                    boolean realmDefaulted = false;
                    if (spec.realmScoped()) {
                        realm = binding != null && binding.realm() != null ? binding.realm()
                                : (String) args.get(InputSchema.REALM);
                        if (realm == null) {
                            realm = admin != null ? admin.system().defaultRealm().orElse(null) : catalog.defaultRealm();
                            realmDefaulted = realm != null;
                        }
                    }
                    if (systemError != null) {
                        result = systemError;
                    }
                    else if (spec.realmScoped() && realm == null) {
                        result = ToolResult.error("realm_required", "Pass the realm argument.");
                    }
                    else if (realmDefaulted && explicit) {
                        result = ToolResult.error("realm_required",
                                "This server does not apply the default realm to " + spec.level().name().toLowerCase()
                                        + " tools (kc-mcp.explicit-target=" + explicitTarget.name().toLowerCase()
                                        + "): pass the realm argument.",
                                "defaultRealm", realm);
                    }
                    else {
                        java.util.Optional<ToolResult> denied = policy.forbids(spec, system, realm, args, ctx, admin);
                        result = denied.isPresent() ? denied.get()
                                : runWithConfirmation(spec, system, admin, realm, args, confirmFlag, ctx);
                    }
                }
            }
        }
        catch (Exception e) {
            LOG.debugf(e, "Tool %s failed", spec.name());
            result = ErrorMapper.map(e);
        }
        audit.record(spec, system, realm, rawArgs, result, ctx, System.nanoTime() - start);
        return result;
    }

    /**
     * Whether a system of that name exists; {@code true} when systems are not wired
     * (tests).
     */
    public boolean hasSystem(String name) {
        return systems == null || name == null || systems.find(name).isPresent();
    }

    public static ToolResult bindingMismatch(EntryBinding binding, String argument, String value) {
        return ToolResult.error("entry_mismatch",
                "This MCP entry is bound to " + binding.describe() + "; the " + argument + " argument '" + value
                        + "' does not match. Leave it out, or use an entry for that " + argument + ".",
                "entry", binding.asMap());
    }

    /**
     * A {@code system} or {@code realm} argument that contradicts the entry's binding,
     * judged on the raw arguments because the schema may not even declare them.
     */
    private static ToolResult bindingMismatch(ToolSpec spec, Map<String, Object> rawArgs, EntryBinding binding) {
        Object system = rawArgs.get(InputSchema.SYSTEM);
        if (system != null && !binding.system().equals(String.valueOf(system))) {
            return bindingMismatch(binding, InputSchema.SYSTEM, String.valueOf(system));
        }
        Object realm = rawArgs.get(InputSchema.REALM);
        if (binding.realm() != null && spec.realmScoped() && realm != null
                && !binding.realm().equals(String.valueOf(realm))) {
            return bindingMismatch(binding, InputSchema.REALM, String.valueOf(realm));
        }
        return null;
    }

    /**
     * The raw arguments with the entry's system and realm filled in where the schema
     * takes them.
     */
    private static Map<String, Object> withBinding(ToolSpec spec, Map<String, Object> rawArgs, EntryBinding binding) {
        Map<String, Object> prepared = new java.util.LinkedHashMap<>(rawArgs);
        io.vertx.core.json.JsonObject props = spec.inputSchema().getJsonObject("properties");
        if (props != null && props.containsKey(InputSchema.SYSTEM)) {
            prepared.put(InputSchema.SYSTEM, binding.system());
        }
        if (binding.realm() != null && spec.realmScoped() && props != null && props.containsKey(InputSchema.REALM)) {
            prepared.put(InputSchema.REALM, binding.realm());
        }
        return prepared;
    }

    private ToolResult runWithConfirmation(ToolSpec spec, String system, KeycloakAdmin admin, String realm,
            Map<String, Object> args, boolean confirmFlag, InvocationContext ctx) throws Exception {
        if (spec.isDestructive()) {
            ConfirmationRequest request = new ConfirmationRequest(spec, system, realm, args, confirmFlag, ctx.caller(),
                    ElicitationPrompter.of(ctx.elicitation(), confirmTimeout));
            Decision decision = confirmer.confirm(request);
            switch (decision.outcome()) {
                case DECLINED -> {
                    return ToolResult.error("cancelled", decision.message() != null ? decision.message()
                            : "The user declined to confirm " + spec.name() + ".");
                }
                case CONFIRMATION_REQUIRED, ABSTAIN -> {
                    return ToolResult.error("confirmation_required",
                            decision.message() != null
                                    ? decision.message() : spec.title() + " is destructive and needs confirmation.",
                            "howTo",
                            confirmFallback.acceptsFlag()
                                    ? "Ask the user, then call again with the same arguments plus confirm: true."
                                    : "Only the user can confirm, through an MCP client that supports elicitation;"
                                            + " confirm: true is not accepted on this server.");
                }
                default -> {
                    // confirmed
                }
            }
        }
        ToolCall call = new ToolCall(realm, args, maxItems, ctx.caller(), system, admin, policy.capabilities(system));
        ToolResult r = spec.handler().handle(call);
        return r == null ? ToolResult.done("ok") : r;
    }

}
