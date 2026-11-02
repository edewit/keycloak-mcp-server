package org.keycloak.mcp.meta;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.InputSchema;
import org.keycloak.mcp.catalog.ToolCatalog;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.exposure.ExposureMode;
import org.keycloak.mcp.exposure.ProgressiveState;
import org.keycloak.mcp.guard.AccessPolicy;
import org.keycloak.mcp.guard.InvocationContext;
import org.keycloak.mcp.guard.ToolInvoker;
import org.keycloak.mcp.search.SearchHit;
import org.keycloak.mcp.search.ToolIndex;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * {@code search_tools} and {@code execute_tool}. Transport-agnostic; {@link McpToolRegistrar} wires them to the
 * Quarkus {@code ToolManager}.
 */
@ApplicationScoped
public class MetaTools {

    public static final String SEARCH_TOOLS = "search_tools";
    public static final String EXECUTE_TOOL = "execute_tool";
    public static final int SEARCH_LIMIT_MAX = 10;
    static final String HINT = "Call execute_tool with name and arguments.";

    private final ToolCatalog catalog;
    private final ToolIndex index;
    private final AccessPolicy policy;
    private final ToolInvoker invoker;
    private final ProgressiveState progressive;
    private final int defaultLimit;

    @Inject
    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            McpServerConfig config) {
        this(catalog, policy, invoker, progressive, config.searchLimitDefault());
    }

    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            int defaultLimit) {
        this.catalog = catalog;
        this.index = new ToolIndex(catalog.all());
        this.policy = policy;
        this.invoker = invoker;
        this.progressive = progressive;
        this.defaultLimit = Math.clamp(defaultLimit, 1, SEARCH_LIMIT_MAX);
    }

    public static boolean isMetaTool(String name) {
        return SEARCH_TOOLS.equals(name) || EXECUTE_TOOL.equals(name);
    }

    public ToolIndex index() {
        return index;
    }

    // ---- search_tools -------------------------------------------------------------------------------------------

    public JsonObject searchSchema() {
        return InputSchema.builder()
                .string("query", "What you want to do, e.g. \"disable user\", \"list clients\", \"ldap sync\"")
                .enumeration("category", "Restrict to one area",
                        java.util.Arrays.stream(Category.values()).map(Category::id).toArray(String[]::new))
                .integer("limit", "Max tools to return").min(1).max(SEARCH_LIMIT_MAX).def(defaultLimit)
                .build();
    }

    public ToolResult search(String query, String categoryArg, Integer limitArg, String connectionId,
            ExposureMode mode) {
        Category category = Category.parse(categoryArg);
        if (categoryArg != null && !categoryArg.isBlank() && category == null) {
            return ToolResult.error("invalid_arguments", "Unknown category '" + categoryArg + "'.",
                    "categories", categoriesJson().getList());
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
        JsonArray tools = new JsonArray();
        List<String> names = new ArrayList<>();
        for (SearchHit hit : hits) {
            tools.add(toolJson(hit.spec()));
            names.add(hit.spec().name());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tools", tools.getList());
        if (hits.isEmpty()) {
            out.put("hint", "No match. Try other words, or call search_tools without a query to see the categories.");
        } else {
            out.put("hint", HINT);
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
        return new JsonObject()
                .put("name", spec.name())
                .put("title", spec.title())
                .put("description", spec.description())
                .put("level", spec.level().name().toLowerCase())
                .put("inputSchema", spec.inputSchema());
    }

    // ---- execute_tool -------------------------------------------------------------------------------------------

    public JsonObject executeSchema() {
        return InputSchema.builder()
                .string("name", "Tool name as returned by search_tools, e.g. keycloak_user_search").required()
                .anyMap("arguments", "Arguments for that tool; pass {} if it takes none").required()
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
            return ToolResult.error("unknown_tool", "No tool named '" + name + "'.",
                    "didYouMean", didYouMean.getList(),
                    "hint", "Use search_tools to find the right tool name.");
        }
        ToolSpec spec = resolved.get();
        Map<String, Object> args = arguments == null ? Map.of() : arguments;
        boolean confirmFlag = Boolean.TRUE.equals(confirm) || Boolean.TRUE.equals(args.get(InputSchema.CONFIRM));
        return invoker.invoke(spec, args, confirmFlag, ctx);
    }
}
