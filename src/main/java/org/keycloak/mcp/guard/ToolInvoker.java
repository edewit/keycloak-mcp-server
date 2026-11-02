package org.keycloak.mcp.guard;

import java.util.List;
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
import org.keycloak.mcp.config.McpServerConfig;

import io.vertx.core.json.JsonObject;

/**
 * The single execution path for every tool, whether called directly or through {@code execute_tool}:
 * policy -> validation -> realm -> confirmation -> handler -> audit.
 */
@ApplicationScoped
public class ToolInvoker {

    private static final Logger LOG = Logger.getLogger(ToolInvoker.class);
    private static final Logger AUDIT = Logger.getLogger("org.keycloak.mcp.audit");

    private final ToolCatalog catalog;
    private final AccessPolicy policy;
    private final Confirmer confirmer;
    private final int maxItems;

    @Inject
    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, McpServerConfig config) {
        this(catalog, policy, confirmer, config.resultMaxItems());
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems) {
        this.catalog = catalog;
        this.policy = policy;
        this.confirmer = confirmer;
        this.maxItems = maxItems;
    }

    public ToolResult invoke(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag, InvocationContext ctx) {
        long start = System.nanoTime();
        ToolResult result;
        String realm = null;
        try {
            if (!policy.permits(spec)) {
                result = ToolResult.error("read_only_mode",
                        "This server runs in read-only mode; " + spec.name() + " is a " + spec.level().name().toLowerCase()
                                + " operation.");
            } else {
                ArgumentValidator.Outcome outcome = ArgumentValidator.validate(spec.inputSchema(), rawArgs);
                if (!outcome.valid()) {
                    result = ToolResult.error("invalid_arguments", "Arguments do not match the tool schema.",
                            "problems", outcome.problems().stream().map(ArgumentValidator.Problem::toMap).toList(),
                            "inputSchema", spec.inputSchema().getMap());
                } else {
                    Map<String, Object> args = outcome.values();
                    if (spec.realmScoped()) {
                        realm = (String) args.get(InputSchema.REALM);
                        if (realm == null) {
                            realm = catalog.defaultRealm();
                        }
                    }
                    if (spec.realmScoped() && realm == null) {
                        result = ToolResult.error("realm_required", "Pass the realm argument.");
                    } else if (spec.realmScoped() && !policy.realmAllowed(realm)) {
                        result = ToolResult.error("realm_not_allowed", "Realm '" + realm + "' is not allowed.",
                                "allowed", List.copyOf(policy.allowedRealms()));
                    } else {
                        result = runWithConfirmation(spec, realm, args, confirmFlag, ctx);
                    }
                }
            }
        } catch (Exception e) {
            LOG.debugf(e, "Tool %s failed", spec.name());
            result = ErrorMapper.map(e);
        }
        audit(spec, realm, result, ctx, System.nanoTime() - start);
        return result;
    }

    private ToolResult runWithConfirmation(ToolSpec spec, String realm, Map<String, Object> args, boolean confirmFlag,
            InvocationContext ctx) throws Exception {
        if (spec.isDestructive()) {
            Confirmer.Decision decision = confirmer.confirm(spec, realm, new JsonObject(args), confirmFlag, ctx);
            switch (decision) {
                case DECLINED -> {
                    return ToolResult.error("cancelled", "The user declined to confirm " + spec.name() + ".");
                }
                case CONFIRMATION_REQUIRED -> {
                    return ToolResult.error("confirmation_required",
                            spec.title() + " is destructive and needs confirmation.",
                            "howTo", "Ask the user, then call again with the same arguments plus confirm: true.");
                }
                default -> {
                    // confirmed
                }
            }
        }
        ToolCall call = new ToolCall(realm, args, maxItems);
        ToolResult r = spec.handler().handle(call);
        return r == null ? ToolResult.done("ok") : r;
    }

    private void audit(ToolSpec spec, String realm, ToolResult result, InvocationContext ctx, long nanos) {
        String outcome = "ok";
        if (result.isError() && result.payload() instanceof Map<?, ?> m && m.get("error") != null) {
            outcome = String.valueOf(m.get("error"));
        } else if (result.isError()) {
            outcome = "error";
        }
        AUDIT.infof("tool=%s level=%s realm=%s outcome=%s via=%s client=%s conn=%s ms=%d",
                spec.name(), spec.level(), realm == null ? "-" : realm, outcome, ctx.via(), ctx.clientName(),
                ctx.connectionId(), nanos / 1_000_000);
    }
}
