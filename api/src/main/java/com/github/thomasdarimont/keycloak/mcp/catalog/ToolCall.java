package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;
import com.github.thomasdarimont.keycloak.mcp.spi.Caller;

/**
 * Validated, coerced input for a {@link ToolHandler}.
 *
 * @param realm resolved realm, or {@code null} for tools that are not realm scoped
 * @param args validated arguments (defaults applied, unknown keys dropped)
 * @param maxItems the configured upper bound for result lists
 * @param caller who is acting ({@link Caller#NONE} when the endpoint is unauthenticated)
 * @param system name of the Keycloak system the call targets
 * @param keycloak admin client of that system ({@code null} only in unit tests)
 * @param capabilities version and features of that system
 * ({@link ServerCapabilities#UNKNOWN} when not read), for handlers whose behavior differs
 * between Keycloak versions
 */
public record ToolCall(String realm, Map<String, Object> args, int maxItems, Caller caller, String system,
        KeycloakAdmin keycloak, ServerCapabilities capabilities) {

    public ToolCall {
        args = Map.copyOf(Objects.requireNonNullElse(args, Map.of()));
        caller = caller == null ? Caller.NONE : caller;
        capabilities = capabilities == null ? ServerCapabilities.UNKNOWN : capabilities;
    }

    public ToolCall(String realm, Map<String, Object> args, int maxItems) {
        this(realm, args, maxItems, Caller.NONE, null, null, null);
    }

    public ToolCall(String realm, Map<String, Object> args, int maxItems, Caller caller) {
        this(realm, args, maxItems, caller, null, null, null);
    }

    public ToolCall(String realm, Map<String, Object> args, int maxItems, Caller caller, String system,
            KeycloakAdmin keycloak) {
        this(realm, args, maxItems, caller, system, keycloak, null);
    }

    /** Admin client of the call's system. */
    public KeycloakAdmin kc() {
        return keycloak;
    }

    public boolean has(String key) {
        return args.get(key) != null;
    }

    public String str(String key) {
        Object v = args.get(key);
        return v == null ? null : v.toString();
    }

    public String str(String key, String defaultValue) {
        String v = str(key);
        return v == null ? defaultValue : v;
    }

    public Integer integer(String key) {
        Object v = args.get(key);
        return v == null ? null : ((Number) v).intValue();
    }

    public int integer(String key, int defaultValue) {
        Integer v = integer(key);
        return v == null ? defaultValue : v;
    }

    public Long longValue(String key) {
        Object v = args.get(key);
        return v == null ? null : ((Number) v).longValue();
    }

    public Boolean bool(String key) {
        Object v = args.get(key);
        return v == null ? null : (Boolean) v;
    }

    public boolean bool(String key, boolean defaultValue) {
        Boolean v = bool(key);
        return v == null ? defaultValue : v;
    }

    @SuppressWarnings("unchecked")
    public List<String> strings(String key) {
        Object v = args.get(key);
        return v == null ? null : (List<String>) v;
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> stringMap(String key) {
        Object v = args.get(key);
        return v == null ? null : (Map<String, String>) v;
    }

    /** Pagination helpers; {@code max} is already clamped by the validator. */
    public int first() {
        return integer("first", 0);
    }

    public int max() {
        return Math.min(integer("max", 20), maxItems);
    }
}
