package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import io.vertx.core.json.JsonObject;

/**
 * Which tool arguments must never be shown or recorded: those the schema declares
 * sensitive ({@link InputSchema.Builder#sensitive()}, JSON Schema {@code writeOnly}),
 * keys of map arguments it declares sensitive
 * ({@link InputSchema.Builder#sensitiveKeys}), and, for undeclared ones, names that end
 * like a secret ({@code password}, {@code clientSecret}, {@code bindCredential},
 * {@code refreshToken}, {@code privateKey}, {@code keyTab}): settings that merely mention
 * the word ({@code passwordPolicy}, {@code accessTokenLifespan}) are not secrets. The
 * audit log, the confirmation prompts and the CIBA device text all ask here.
 */
public final class Sensitive {

    /** What replaces a sensitive value. */
    public static final String MASK = "***";

    /**
     * How the names of secrets end, when nothing is declared (compared in lower case).
     */
    static final List<String> NAME_HINTS = List.of("password", "passwd", "secret", "credential", "credentials", "token",
            "key", "keytab", "pin", "otp");

    private Sensitive() {
    }

    /**
     * Whether a name ends like a secret ({@code password}, {@code client_secret},
     * {@code apiKey}).
     */
    public static boolean byName(String name) {
        String n = name == null ? "" : name.toLowerCase(Locale.ROOT);
        return NAME_HINTS.stream().anyMatch(n::endsWith);
    }

    /**
     * Whether the argument is declared sensitive in the schema or looks like a secret.
     */
    public static boolean argument(JsonObject schema, String name) {
        JsonObject prop = property(schema, name);
        return prop != null && prop.getBoolean("writeOnly", false) || byName(name);
    }

    /** Whether a key of a map argument is declared sensitive or looks like a secret. */
    public static boolean key(JsonObject schema, String argument, String key) {
        JsonObject prop = property(schema, argument);
        JsonObject keys = prop == null ? null : prop.getJsonObject("properties");
        JsonObject k = keys == null ? null : keys.getJsonObject(key);
        return k != null && k.getBoolean("writeOnly", false) || byName(key);
    }

    /**
     * The arguments with every sensitive value, and every sensitive key of a map
     * argument, replaced by {@link #MASK}.
     *
     * @param schema the tool's input schema; {@code null} applies the name hints only
     */
    public static Map<String, Object> redact(JsonObject schema, Map<String, Object> args) {
        if (args == null || args.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        args.forEach((name, value) -> {
            if (value != null && argument(schema, name)) {
                out.put(name, MASK);
            }
            else if (value instanceof Map<?, ?> map) {
                Map<String, Object> inner = new LinkedHashMap<>();
                map.forEach((k, v) -> inner.put(String.valueOf(k),
                        v != null && key(schema, name, String.valueOf(k)) ? MASK : v));
                out.put(name, inner);
            }
            else {
                out.put(name, value);
            }
        });
        return out;
    }

    private static JsonObject property(JsonObject schema, String name) {
        JsonObject props = schema == null ? null : schema.getJsonObject("properties");
        return props == null ? null : props.getJsonObject(name);
    }
}
