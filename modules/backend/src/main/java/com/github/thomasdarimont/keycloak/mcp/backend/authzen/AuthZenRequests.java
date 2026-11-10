package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Turns one tool call into an AuthZEN evaluation request (OpenID AuthZEN Authorization
 * API 1.0, {@code POST /access/v1/evaluation}):
 * <ul>
 * <li>{@code subject}: the caller from the token, never from the arguments: {@code user}
 * or, for a service account token, {@code client}, with realm, roles, delegation and the
 * acting client; {@code anonymous} while the endpoint is unauthenticated</li>
 * <li>{@code action}: the tool name, with its level, category and the Admin REST
 * operation it performs ({@code PUT /admin/realms/{realm}/users/{user-id}})</li>
 * <li>{@code resource}: what the call acts on, read from the operation's path bindings:
 * the innermost path parameter the call fills ({@code users/{user-id}} with
 * {@code id=8f1c} is {@code user 8f1c}), the enclosing ones in {@code properties.path}; a
 * call that names nothing in its path (a create, a list) acts on the realm, a global tool
 * on the Keycloak system</li>
 * <li>{@code context}: system, realm, the acting client ({@code azp}, {@code act}), the
 * time and, with {@code send-args}, the arguments with every sensitive value masked</li>
 * </ul>
 */
final class AuthZenRequests {

    static final String REALM_PREFIX = "/admin/realms/{realm}";

    /** Segments that are not a collection of their own: the one before them is. */
    private static final Set<String> INNER_SEGMENTS = Set.of("instances", "models");

    private AuthZenRequests() {
    }

    static JsonObject evaluation(AccessCheck.Context ctx, boolean sendArgs, Instant now) {
        ToolSpec tool = ctx.tool();
        return new JsonObject().put("subject", subject(ctx.caller()))
            .put("action", action(tool))
            .put("resource", resource(ctx))
            .put("context", context(ctx, sendArgs, now));
    }

    static JsonObject subject(Caller caller) {
        if (caller == null || caller.isAnonymous()) {
            return new JsonObject().put("type", "anonymous").put("id", "anonymous");
        }
        JsonObject props = new JsonObject().put("delegated", caller.delegated())
            .put("roles", new JsonArray(new ArrayList<>(new TreeSet<>(caller.roles()))));
        putIfPresent(props, "name", caller.name());
        putIfPresent(props, "realm", caller.realm());
        putIfPresent(props, "issuer", string(caller.claim("iss")));
        putIfPresent(props, "client_id", actingClient(caller));
        return new JsonObject().put("type", isServiceAccount(caller) ? "client" : "user")
            .put("id", caller.subject())
            .put("properties", props);
    }

    static JsonObject action(ToolSpec tool) {
        JsonObject props = new JsonObject().put("level", tool.level().name().toLowerCase(Locale.ROOT))
            .put("category", tool.category().id());
        ApiOperation op = primary(tool);
        if (op != null) {
            props.put("operation", op.toString()).put("method", op.method().toUpperCase(Locale.ROOT));
        }
        return new JsonObject().put("name", tool.name()).put("properties", props);
    }

    static JsonObject resource(AccessCheck.Context ctx) {
        ToolSpec tool = ctx.tool();
        JsonObject props = new JsonObject();
        putIfPresent(props, "system", ctx.system());
        putIfPresent(props, "realm", ctx.realm());
        ApiOperation op = primary(tool);
        List<JsonObject> path = op == null ? List.of() : pathResources(op, ctx.args());
        if (!path.isEmpty()) {
            JsonObject innermost = path.getLast();
            if (path.size() > 1) {
                props.put("path", new JsonArray(new ArrayList<>(path.subList(0, path.size() - 1))));
            }
            return innermost.copy().put("properties", props);
        }
        if (op != null) {
            putIfPresent(props, "collection", collection(op));
        }
        if (ctx.realm() != null) {
            return new JsonObject().put("type", "realm").put("id", ctx.realm()).put("properties", props);
        }
        return new JsonObject().put("type", "system")
            .put("id", ctx.system() == null ? "default" : ctx.system())
            .put("properties", props);
    }

    static JsonObject context(AccessCheck.Context ctx, boolean sendArgs, Instant now) {
        JsonObject c = new JsonObject();
        putIfPresent(c, "system", ctx.system());
        putIfPresent(c, "realm", ctx.realm());
        Caller caller = ctx.caller();
        if (caller != null && !caller.isAnonymous()) {
            JsonObject agent = new JsonObject();
            putIfPresent(agent, "client_id", actingClient(caller));
            Object act = caller.claim("act");
            if (act instanceof Map<?, ?> m) {
                agent.put("act", new JsonObject(plainMap(m)));
            }
            if (!agent.isEmpty()) {
                c.put("agent", agent);
            }
        }
        c.put("time", now.toString());
        if (sendArgs) {
            c.put("args", new JsonObject(Sensitive.redact(ctx.tool().inputSchema(), ctx.args())));
        }
        return c;
    }

    /**
     * The operation the call is about: a tool that reads before it writes is about the
     * write.
     */
    static ApiOperation primary(ToolSpec tool) {
        if (tool.api().isEmpty()) {
            return null;
        }
        if (!tool.isReadOnly()) {
            for (ApiOperation op : tool.api()) {
                if (!"get".equals(op.method())) {
                    return op;
                }
            }
        }
        return tool.api().getFirst();
    }

    /**
     * The resources the call's arguments fill into the path, outermost first; parameters
     * the handler derives, and the realm, do not count.
     */
    static List<JsonObject> pathResources(ApiOperation op, Map<String, Object> args) {
        List<JsonObject> out = new ArrayList<>();
        String[] segments = relative(op.path()).split("/");
        for (int i = 0; i < segments.length; i++) {
            String s = segments[i];
            if (!s.startsWith("{") || !s.endsWith("}")) {
                continue;
            }
            String argument = op.pathParams().get(s.substring(1, s.length() - 1));
            if (argument == null || ApiOperation.DERIVED.equals(argument)) {
                continue;
            }
            Object value = args == null ? null : args.get(argument);
            String type = typeBefore(segments, i);
            if (value == null || type == null) {
                continue;
            }
            out.add(new JsonObject().put("type", type).put("id", String.valueOf(value)));
        }
        return out;
    }

    /** The last literal segment of the path, singular: what a create or list acts on. */
    static String collection(ApiOperation op) {
        String[] segments = relative(op.path()).split("/");
        return typeBefore(segments, segments.length);
    }

    private static String typeBefore(String[] segments, int index) {
        for (int j = index - 1; j >= 0; j--) {
            String s = segments[j];
            if (s.isEmpty() || s.startsWith("{") || INNER_SEGMENTS.contains(s)) {
                continue;
            }
            return singular(s);
        }
        return null;
    }

    static String singular(String segment) {
        String s = segment.endsWith("-by-id") ? segment.substring(0, segment.length() - "-by-id".length()) : segment;
        if (s.endsWith("ies")) {
            return s.substring(0, s.length() - 3) + "y";
        }
        if (s.endsWith("s") && !s.endsWith("ss")) {
            return s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static String relative(String path) {
        if (path.startsWith(REALM_PREFIX)) {
            return path.substring(REALM_PREFIX.length());
        }
        return path.startsWith("/admin/") ? path.substring("/admin".length()) : path;
    }

    /**
     * A Keycloak service account token: {@code client_id} (Keycloak's service account
     * mapper) or the {@code service-account-} username.
     */
    static boolean isServiceAccount(Caller caller) {
        String username = string(caller.claim("preferred_username"));
        return caller.claim("client_id") != null || username != null && username.startsWith("service-account-");
    }

    private static String actingClient(Caller caller) {
        String azp = string(caller.claim("azp"));
        return azp != null ? azp : string(caller.claim("client_id"));
    }

    private static String string(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> plainMap(Map<?, ?> m) {
        return (Map<String, Object>) m;
    }

    private static void putIfPresent(JsonObject o, String key, String value) {
        if (value != null && !value.isBlank()) {
            o.put(key, value);
        }
    }
}
