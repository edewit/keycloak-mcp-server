package org.keycloak.mcp.meta;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.exposure.ExposurePolicy;
import org.keycloak.mcp.guard.AccessPolicy;
import org.keycloak.mcp.guard.InvocationContext;
import org.keycloak.mcp.guard.ToolInvoker;

import io.quarkiverse.mcp.server.TextContent;
import io.quarkiverse.mcp.server.ToolManager;
import io.quarkiverse.mcp.server.ToolManager.ToolAnnotations;
import io.quarkiverse.mcp.server.ToolManager.ToolArguments;
import io.quarkiverse.mcp.server.ToolResponse;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonObject;

/**
 * Registers the meta-tools and every permitted catalog tool with the Quarkus {@link ToolManager} at startup.
 * Visibility in {@code tools/list} is then decided per request by the {@link org.keycloak.mcp.exposure.ExposureToolFilter}.
 */
@ApplicationScoped
public class McpToolRegistrar {

    private static final Logger LOG = Logger.getLogger(McpToolRegistrar.class);
    /** Handlers block on the admin REST client, so they run on virtual threads (no synchronized in our code). */
    private static final boolean VIRTUAL_THREADS = true;

    @Inject
    ToolManager toolManager;
    @Inject
    ToolCatalog catalog;
    @Inject
    MetaTools metaTools;
    @Inject
    ToolInvoker invoker;
    @Inject
    AccessPolicy policy;
    @Inject
    ExposurePolicy exposure;
    @Inject
    org.keycloak.mcp.spi.CallerProvider callers;
    @Inject
    org.keycloak.mcp.guard.CallerAuth callerAuth;

    void onStart(@Observes StartupEvent event) {
        registerMetaTools();
        int registered = 0;
        for (ToolSpec spec : catalog.all()) {
            if (!policy.permits(spec)) {
                continue;
            }
            registerCatalogTool(spec);
            registered++;
        }
        LOG.infof("Keycloak MCP %s: %d/%d tools registered, exposure=%s, readOnly=%s, delegation=%s, callers=%s",
                buildVersion(), registered, catalog.size(), exposure.mode(), policy.readOnly(), callerAuth.delegation(),
                callerAuth.required() ? "required" : callerAuth.oidcEnabled() ? "optional" : "anonymous");
    }

    /** Version and build time from the jar manifest, so a stale deployment is visible in the first log line. */
    static String buildVersion() {
        Package p = McpToolRegistrar.class.getPackage();
        String v = p == null ? null : p.getImplementationVersion();
        String version = v == null ? "dev" : v;
        String built = org.eclipse.microprofile.config.ConfigProvider.getConfig()
                .getOptionalValue("keycloak-mcp.build-time", String.class).orElse(null);
        return built == null ? version : version + " (built " + built + ")";
    }

    private void registerMetaTools() {
        toolManager.newTool(MetaTools.SEARCH_TOOLS)
                .setTitle("Search Keycloak tools")
                .setDescription("Find the Keycloak admin tool for a task. Returns name, description and input schema; "
                        + "then call execute_tool. Call without arguments to list the tool categories.")
                .setAnnotations(new ToolAnnotations("Search Keycloak tools", true, false, true, false))
                .setInputSchema(metaTools.searchSchema())
                .setHandler(args -> toResponse(metaTools.search(
                        str(args.args(), "query"), str(args.args(), "category"), intOf(args.args(), "limit"),
                        args.connection() == null ? null : args.connection().id(), exposure.mode(),
                        InvocationContext.of(args, MetaTools.SEARCH_TOOLS)
                                .withCaller(callers.current(args), callers.accessToken(args)))), VIRTUAL_THREADS)
                .register();

        toolManager.newTool(MetaTools.WHOAMI)
                .setTitle("Who am I")
                .setDescription("Who the Keycloak calls of this session run as (the signed-in user or the server's "
                        + "service account), their realm-management roles with readable labels, and what they may "
                        + "view or manage. Call it when an action was forbidden or the user asks what they can do.")
                .setAnnotations(new ToolAnnotations("Who am I", true, false, true, false))
                .setInputSchema(metaTools.whoamiSchema())
                .setHandler(args -> toResponse(metaTools.whoami(str(args.args(), "language"),
                        str(args.args(), InputSchema.SYSTEM), InvocationContext.of(args, MetaTools.WHOAMI)
                                .withCaller(callers.current(args), callers.accessToken(args)))), VIRTUAL_THREADS)
                .register();

        toolManager.newTool(MetaTools.EXECUTE_TOOL)
                .setTitle("Execute a Keycloak tool")
                .setDescription("Run a Keycloak admin tool found via search_tools: name plus its arguments object.")
                .setAnnotations(new ToolAnnotations("Execute a Keycloak tool", false, true, false, false))
                .setInputSchema(metaTools.executeSchema())
                .setHandler(args -> {
                    Map<String, Object> a = args.args();
                    return toResponse(metaTools.execute(str(a, "name"), mapOf(a.get("arguments")),
                            boolOf(a.get(InputSchema.CONFIRM)),
                            InvocationContext.of(args, MetaTools.EXECUTE_TOOL)
                                    .withCaller(callers.current(args), callers.accessToken(args))));
                }, VIRTUAL_THREADS)
                .register();
    }

    private void registerCatalogTool(ToolSpec spec) {
        toolManager.newTool(spec.name())
                .setTitle(spec.title())
                .setDescription(spec.description())
                .setAnnotations(new ToolAnnotations(spec.title(), spec.isReadOnly(), spec.isDestructive(),
                        spec.idempotent(), false))
                .setInputSchema(withConfirm(spec))
                .setHandler(args -> {
                    Map<String, Object> a = args.args();
                    boolean confirm = Boolean.TRUE.equals(boolOf(a.get(InputSchema.CONFIRM)));
                    return toResponse(invoker.invoke(spec, a, confirm,
                            InvocationContext.of(args, "direct").withCaller(callers.current(args), callers.accessToken(args))));
                }, VIRTUAL_THREADS)
                .register();
    }

    /** Direct destructive tools get an optional {@code confirm} flag for clients without elicitation. */
    private static JsonObject withConfirm(ToolSpec spec) {
        if (!spec.isDestructive()) {
            return spec.inputSchema();
        }
        JsonObject schema = spec.inputSchema().copy();
        schema.getJsonObject("properties").put(InputSchema.CONFIRM, new JsonObject()
                .put("type", "boolean")
                .put("description", "Set true after the user confirmed this destructive operation"));
        return schema;
    }

    static ToolResponse toResponse(ToolResult result) {
        return new ToolResponse(result.isError(), java.util.List.of(new TextContent(result.toJson())));
    }

    private static String str(Map<String, Object> args, String key) {
        Object v = args.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static Integer intOf(Map<String, Object> args, String key) {
        Object v = args.get(key);
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s && !s.isBlank()) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Boolean boolOf(Object v) {
        if (v instanceof Boolean b) {
            return b;
        }
        if (v instanceof String s) {
            return Boolean.parseBoolean(s.trim());
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOf(Object v) {
        if (v instanceof JsonObject jo) {
            return jo.getMap();
        }
        if (v instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        if (v instanceof String s && s.trim().startsWith("{")) {
            try {
                return new JsonObject(s).getMap();
            } catch (RuntimeException e) {
                return Map.of();
            }
        }
        return Map.of();
    }
}
