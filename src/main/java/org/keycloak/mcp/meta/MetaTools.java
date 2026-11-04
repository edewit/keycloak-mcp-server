package org.keycloak.mcp.meta;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.DelegationMode;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.exposure.ExposureMode;
import org.keycloak.mcp.exposure.ProgressiveState;
import org.keycloak.mcp.guard.AccessPolicy;
import org.keycloak.mcp.guard.GrantedRoles;
import org.keycloak.mcp.guard.InvocationContext;
import org.keycloak.mcp.guard.ToolInvoker;
import org.keycloak.mcp.search.SearchHit;
import org.keycloak.mcp.search.ToolIndex;
import org.keycloak.mcp.spi.Caller;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * {@code search_tools}, {@code execute_tool} and {@code whoami}. Transport-agnostic;
 * {@link McpToolRegistrar} wires them to the Quarkus {@code ToolManager}.
 */
@ApplicationScoped
public class MetaTools {

    public static final String SEARCH_TOOLS = "search_tools";
    public static final String EXECUTE_TOOL = "execute_tool";
    public static final String WHOAMI = "whoami";
    public static final int SEARCH_LIMIT_MAX = 10;
    static final String HINT = "Call execute_tool with name and arguments.";
    static final String FORBIDDEN_HINT = "Tools marked allowed=false need realm-management roles the current caller "
            + "does not hold: do not call them, tell the user which roles are missing (whoami shows the details).";

    private final ToolCatalog catalog;
    private final ToolIndex index;
    private final AccessPolicy policy;
    private final ToolInvoker invoker;
    private final ProgressiveState progressive;
    private final int defaultLimit;
    private final DelegationMode delegation;

    @Inject
    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            McpServerConfig config) {
        this(catalog, policy, invoker, progressive, config.searchLimitDefault(), config.delegation());
    }

    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            int defaultLimit) {
        this(catalog, policy, invoker, progressive, defaultLimit, DelegationMode.OFF);
    }

    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            int defaultLimit, DelegationMode delegation) {
        this.catalog = catalog;
        this.index = new ToolIndex(catalog.all());
        this.policy = policy;
        this.invoker = invoker;
        this.progressive = progressive;
        this.defaultLimit = Math.clamp(defaultLimit, 1, SEARCH_LIMIT_MAX);
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
    }

    /**
     * In delegation mode {@code forward} an authenticated caller acts on their own behalf
     * (as in the invoker).
     */
    private InvocationContext effective(InvocationContext ctx) {
        if (delegation == DelegationMode.FORWARD && ctx.callerToken() != null && !ctx.caller().delegated()) {
            return ctx.withCaller(ctx.caller().asDelegated());
        }
        return ctx;
    }

    public static boolean isMetaTool(String name) {
        return SEARCH_TOOLS.equals(name) || EXECUTE_TOOL.equals(name) || WHOAMI.equals(name);
    }

    public ToolIndex index() {
        return index;
    }

    // ---- search_tools
    // -------------------------------------------------------------------------------------------

    public JsonObject searchSchema() {
        return InputSchema.builder()
            .string("query", "What you want to do, e.g. \"disable user\", \"list clients\", \"ldap sync\"")
            .enumeration("category", "Restrict to one area",
                    java.util.Arrays.stream(Category.values()).map(Category::id).toArray(String[]::new))
            .integer("limit", "Max tools to return")
            .min(1)
            .max(SEARCH_LIMIT_MAX)
            .def(defaultLimit)
            .build();
    }

    public ToolResult search(String query, String categoryArg, Integer limitArg, String connectionId,
            ExposureMode mode) {
        return search(query, categoryArg, limitArg, connectionId, mode, InvocationContext.none());
    }

    /**
     * @param ctx the calling session; when its roles are known, hits the caller may not
     * use are kept in the result but marked {@code allowed=false} with their
     * {@code missingRoles}, so the model can explain instead of trying
     */
    public ToolResult search(String query, String categoryArg, Integer limitArg, String connectionId, ExposureMode mode,
            InvocationContext rawCtx) {
        InvocationContext ctx = effective(rawCtx);
        Category category = Category.parse(categoryArg);
        if (categoryArg != null && !categoryArg.isBlank() && category == null) {
            return ToolResult.error("invalid_arguments", "Unknown category '" + categoryArg + "'.", "categories",
                    categoriesJson().getList());
        }
        boolean noQuery = query == null || query.isBlank();
        if (noQuery && category == null) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("categories", categoriesJson().getList());
            out.put("hint", "Call search_tools again with a query or a category.");
            return ToolResult.ok(out);
        }
        int limit = limitArg == null ? defaultLimit : Math.clamp(limitArg, 1, SEARCH_LIMIT_MAX);
        List<SearchHit> hits = index.search(query, category, limit, policy::visibleNow);
        GrantedRoles granted = policy.granted(catalog.defaultSystem(), ctx);
        boolean judge = granted != null && granted.known();
        JsonArray tools = new JsonArray();
        List<String> names = new ArrayList<>();
        boolean anyForbidden = false;
        for (SearchHit hit : hits) {
            JsonObject tool = toolJson(hit.spec());
            if (judge) {
                Set<String> missing = granted.missingAnyRealm(hit.spec().requiredRoles());
                if (!missing.isEmpty()) {
                    tool.put("allowed", false).put("missingRoles", new JsonArray(List.copyOf(missing)));
                    anyForbidden = true;
                }
            }
            tools.add(tool);
            names.add(hit.spec().name());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tools", tools.getList());
        if (hits.isEmpty()) {
            out.put("hint", "No match. Try other words, or call search_tools without a query to see the categories.");
        }
        else {
            out.put("hint", anyForbidden ? HINT + " " + FORBIDDEN_HINT : HINT);
        }
        if (mode == ExposureMode.PROGRESSIVE && connectionId != null && !names.isEmpty()) {
            if (progressive.surface(connectionId, names)) {
                out.put("listChanged", true);
            }
        }
        return ToolResult.ok(out);
    }

    public JsonArray categoriesJson() {
        Map<Category, Integer> counts = new TreeMap<>();
        for (ToolSpec spec : catalog.all()) {
            if (policy.visibleNow(spec)) {
                counts.merge(spec.category(), 1, Integer::sum);
            }
        }
        JsonArray arr = new JsonArray();
        for (Category c : Category.values()) {
            int n = counts.getOrDefault(c, 0);
            if (n == 0) {
                continue;
            }
            arr.add(new JsonObject().put("category", c.id()).put("tools", n).put("about", c.blurb()));
        }
        return arr;
    }

    public static JsonObject toolJson(ToolSpec spec) {
        return new JsonObject().put("name", spec.name())
            .put("title", spec.title())
            .put("description", spec.description())
            .put("level", spec.level().name().toLowerCase())
            .put("inputSchema", spec.inputSchema());
    }

    // ---- whoami
    // -------------------------------------------------------------------------------------------------

    public JsonObject whoamiSchema() {
        InputSchema.Builder b = InputSchema.builder()
            .string("language", "Language for the role labels, e.g. en or de (default en)");
        if (!catalog.systems().isEmpty()) {
            b.enumeration(InputSchema.SYSTEM, "Keycloak system to report on", catalog.systems().toArray(String[]::new));
        }
        return b.build();
    }

    /**
     * Who the Keycloak calls of this session run as and what they may do: the caller (or
     * the server's service account), the realm-management roles per realm with readable
     * labels, a per-area summary and how many tools that unlocks.
     */
    public ToolResult whoami(String languageArg, String systemArg, InvocationContext rawCtx) {
        InvocationContext ctx = effective(rawCtx);
        String language = RoleLabels.language(languageArg);
        String system = systemArg != null && !systemArg.isBlank() ? systemArg.trim() : catalog.defaultSystem();
        if (system != null && !catalog.systems().isEmpty() && !catalog.systems().contains(system)) {
            return ToolResult.error("unknown_system", "No Keycloak system named '" + system + "'.", "systems",
                    catalog.systems());
        }
        Caller caller = ctx.caller();
        Map<String, Object> out = new LinkedHashMap<>();
        if (caller.isAnonymous()) {
            out.put("caller", "anonymous");
        }
        else {
            Map<String, Object> who = new LinkedHashMap<>();
            who.put("username", caller.name());
            who.put("subject", caller.subject());
            if (caller.realm() != null) {
                who.put("realm", caller.realm());
            }
            out.put("caller", who);
        }
        boolean delegated = caller.delegated() && ctx.callerToken() != null;
        out.put("keycloakCallsRunAs",
                delegated ? "the caller's own account (delegated)" : "the server's service account");
        if (system != null) {
            out.put("system", system);
        }
        if (policy.readOnly()) {
            out.put("readOnly", true);
        }
        GrantedRoles granted = policy.granted(system, ctx);
        if (granted == null || !granted.known()) {
            out.put("roles", "unknown");
            out.put("hint",
                    delegated
                            ? "The caller's token carries no realm-management roles; Keycloak will refuse admin calls."
                            : "The server's roles are not checked up front; Keycloak decides per call.");
            out.put("tools", toolCounts(granted));
            return ToolResult.ok(out);
        }
        if (granted.superAdmin()) {
            out.put("superAdmin", true);
            out.put("roles", List.of(roleJson("admin", language)));
            out.put("can", "everything in every realm");
        }
        else {
            Map<String, Object> rolesByRealm = new LinkedHashMap<>();
            Map<String, Object> canByRealm = new LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : granted.byRealm().entrySet()) {
                List<Map<String, Object>> roles = new ArrayList<>();
                for (String role : e.getValue().stream().sorted().toList()) {
                    roles.add(roleJson(role, language));
                }
                rolesByRealm.put(e.getKey(), roles);
                canByRealm.put(e.getKey(), RoleLabels.capabilities(granted, e.getKey()));
            }
            out.put("roles", rolesByRealm);
            out.put("can", canByRealm);
            out.put("canLevels",
                    "manage = read and write, view = read only, query = look up by id only, none = no access");
        }
        out.put("labelLanguage", language);
        out.put("tools", toolCounts(granted));
        out.put("hint", "search_tools marks tools the caller may not use with allowed=false.");
        return ToolResult.ok(out);
    }

    private static Map<String, Object> roleJson(String role, String language) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("role", role);
        m.put("label", RoleLabels.label(role, language));
        return m;
    }

    /** How many permitted catalog tools the roles unlock, and how many they block. */
    private Map<String, Object> toolCounts(GrantedRoles granted) {
        int allowed = 0;
        int forbidden = 0;
        for (ToolSpec spec : catalog.all()) {
            if (!policy.permits(spec)) {
                continue;
            }
            if (granted != null && granted.known() && !granted.permitsAnyRealm(spec.requiredRoles())) {
                forbidden++;
            }
            else {
                allowed++;
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allowed", allowed);
        m.put("forbidden", forbidden);
        return m;
    }

    // ---- execute_tool
    // -------------------------------------------------------------------------------------------

    public JsonObject executeSchema() {
        return InputSchema.builder()
            .string("name", "Tool name as returned by search_tools, e.g. keycloak_user_search")
            .required()
            .anyMap("arguments", "Arguments for that tool; pass {} if it takes none")
            .required()
            .bool(InputSchema.CONFIRM, "Set true to confirm a destructive operation after asking the user")
            .build();
    }

    public ToolResult execute(String name, Map<String, Object> arguments, Boolean confirm, InvocationContext ctx) {
        Optional<ToolSpec> resolved = catalog.resolve(name);
        if (resolved.isEmpty()) {
            if (isMetaTool(name == null ? "" : ToolCatalog.normalize(name))) {
                return ToolResult.error("invalid_arguments", "Call " + name + " directly, not through execute_tool.");
            }
            List<SearchHit> similar = index.similarNames(name == null ? "" : name, 3, policy::visibleNow);
            JsonArray didYouMean = new JsonArray();
            for (SearchHit hit : similar) {
                didYouMean.add(toolJson(hit.spec()));
            }
            return ToolResult.error("unknown_tool", "No tool named '" + name + "'.", "didYouMean", didYouMean.getList(),
                    "hint", "Use search_tools to find the right tool name.");
        }
        ToolSpec spec = resolved.get();
        Map<String, Object> args = arguments == null ? Map.of() : arguments;
        boolean confirmFlag = Boolean.TRUE.equals(confirm) || Boolean.TRUE.equals(args.get(InputSchema.CONFIRM));
        return invoker.invoke(spec, args, confirmFlag, ctx);
    }
}
