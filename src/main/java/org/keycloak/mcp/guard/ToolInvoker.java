package org.keycloak.mcp.guard;

import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.keycloak.mcp.catalog.ArgumentValidator;
import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.DelegationMode;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.KeycloakSystems;

import io.vertx.core.json.JsonObject;

/**
 * The single execution path for every tool, whether called directly or through
 * {@code execute_tool}: policy -> validation -> realm -> confirmation -> handler ->
 * audit. In delegation mode {@code forward} the caller's token replaces the server's
 * credentials for the handler and the role checks.
 */
@ApplicationScoped
public class ToolInvoker {

    private static final Logger LOG = Logger.getLogger(ToolInvoker.class);
    private static final Logger AUDIT = Logger.getLogger("org.keycloak.mcp.audit");

    private final ToolCatalog catalog;
    private final AccessPolicy policy;
    private final Confirmer confirmer;
    private final int maxItems;
    private final KeycloakSystems systems;
    private final DelegationMode delegation;

    @Inject
    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, McpServerConfig config,
            KeycloakSystems systems) {
        this(catalog, policy, confirmer, config.resultMaxItems(), systems, config.delegation());
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
        this.catalog = catalog;
        this.policy = policy;
        this.confirmer = confirmer;
        this.maxItems = maxItems;
        this.systems = systems;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
    }

    public ToolResult invoke(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag, InvocationContext ctx) {
        long start = System.nanoTime();
        ToolResult result;
        String realm = null;
        String system = null;
        try {
            if (delegation == DelegationMode.FORWARD && ctx.callerToken() == null) {
                result = ToolResult.error("caller_required", "This server runs every Keycloak call with the caller's "
                        + "own token; connect through an authenticated (OAuth) MCP session first.");
            }
            else if (delegation == DelegationMode.FORWARD && !ctx.caller().delegated()) {
                return invoke(spec, rawArgs, confirmFlag, ctx.withCaller(ctx.caller().asDelegated()));
            }
            else if (!policy.permits(spec)) {
                result = policy.forbids(spec, null).orElseThrow();
            }
            else {
                ArgumentValidator.Outcome outcome = ArgumentValidator.validate(spec.inputSchema(), rawArgs);
                if (!outcome.valid()) {
                    result = ToolResult.error("invalid_arguments", "Arguments do not match the tool schema.",
                            "problems", outcome.problems().stream().map(ArgumentValidator.Problem::toMap).toList(),
                            "inputSchema", spec.inputSchema().getMap());
                }
                else {
                    Map<String, Object> args = outcome.values();
                    KeycloakAdmin admin = null;
                    ToolResult systemError = null;
                    if (systems != null) {
                        String requested = (String) args.get(InputSchema.SYSTEM);
                        system = requested != null ? requested : systems.defaultName().orElse(null);
                        if (system == null) {
                            systemError = ToolResult.error("system_required", "Pass the system argument.", "systems",
                                    systems.names());
                        }
                        else if (systems.find(system).isEmpty()) {
                            systemError = ToolResult.error("unknown_system",
                                    "No Keycloak system named '" + system + "'.", "systems", systems.names());
                        }
                        else {
                            admin = systems.get(system);
                            if (delegation == DelegationMode.FORWARD) {
                                admin = admin.forToken(ctx.callerToken());
                            }
                        }
                    }
                    if (spec.realmScoped()) {
                        realm = (String) args.get(InputSchema.REALM);
                        if (realm == null) {
                            realm = admin != null ? admin.system().defaultRealm().orElse(null) : catalog.defaultRealm();
                        }
                    }
                    if (systemError != null) {
                        result = systemError;
                    }
                    else if (spec.realmScoped() && realm == null) {
                        result = ToolResult.error("realm_required", "Pass the realm argument.");
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
        audit(spec, system, realm, result, ctx, System.nanoTime() - start);
        return result;
    }

    private ToolResult runWithConfirmation(ToolSpec spec, String system, KeycloakAdmin admin, String realm,
            Map<String, Object> args, boolean confirmFlag, InvocationContext ctx) throws Exception {
        if (spec.isDestructive()) {
            Confirmer.Decision decision = confirmer.confirm(spec, realm, new JsonObject(args), confirmFlag, ctx);
            switch (decision) {
                case DECLINED -> {
                    return ToolResult.error("cancelled", "The user declined to confirm " + spec.name() + ".");
                }
                case CONFIRMATION_REQUIRED -> {
                    return ToolResult.error("confirmation_required",
                            spec.title() + " is destructive and needs confirmation.", "howTo",
                            "Ask the user, then call again with the same arguments plus confirm: true.");
                }
                default -> {
                    // confirmed
                }
            }
        }
        ToolCall call = new ToolCall(realm, args, maxItems, ctx.caller(), system, admin);
        ToolResult r = spec.handler().handle(call);
        return r == null ? ToolResult.done("ok") : r;
    }

    private void audit(ToolSpec spec, String system, String realm, ToolResult result, InvocationContext ctx,
            long nanos) {
        String outcome = "ok";
        if (result.isError() && result.payload() instanceof Map<?, ?> m && m.get("error") != null) {
            outcome = String.valueOf(m.get("error"));
        }
        else if (result.isError()) {
            outcome = "error";
        }
        AUDIT.infof("tool=%s level=%s system=%s realm=%s outcome=%s via=%s caller=%s%s client=%s conn=%s ms=%d",
                spec.name(), spec.level(), system == null ? "-" : system, realm == null ? "-" : realm, outcome,
                ctx.via(), ctx.caller().isAnonymous() ? "-" : ctx.caller().name() + "(" + ctx.caller().subject() + ")",
                ctx.caller().delegated() ? " delegated" : "", ctx.clientName(), ctx.connectionId(), nanos / 1_000_000);
    }
}
