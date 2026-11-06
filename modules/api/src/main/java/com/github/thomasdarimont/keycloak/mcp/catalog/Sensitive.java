package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import io.vertx.core.json.JsonArray;
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
     * How deep nested maps and lists are looked into; anything deeper is masked as a
     * whole.
     */
    static final int MAX_DEPTH = 8;

    /** Longest audit message kept. */
    static final int MAX_MESSAGE = 500;

    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern BEARER = Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b([a-z_]*(?:password|passwd|secret|credential|token))([\"']?\\s*[:=]\\s*[\"']?)([^\\s\"',;&}]+)");

    /**
     * The arguments with every sensitive value replaced by {@link #MASK}: declared
     * arguments and declared keys of map arguments, and at every depth of nested maps,
     * JSON objects and lists the names that end like a secret; deeper than
     * {@link #MAX_DEPTH} levels a value is masked as a whole.
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
            else {
                out.put(name, nested(value, schema, name, 1));
            }
        });
        return out;
    }

    /**
     * A nested value: map keys checked (declared ones on the first level, name hints on
     * all), lists walked.
     */
    private static Object nested(Object value, JsonObject schema, String argument, int depth) {
        if (value instanceof JsonObject json) {
            value = json.getMap();
        }
        else if (value instanceof JsonArray array) {
            value = array.getList();
        }
        if (!(value instanceof Map<?, ?>) && !(value instanceof Collection<?>)) {
            return value;
        }
        if (depth > MAX_DEPTH) {
            return MASK;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> inner = new LinkedHashMap<>();
            map.forEach((k, v) -> {
                String key = String.valueOf(k);
                boolean secret = depth == 1 ? key(schema, argument, key) : byName(key);
                inner.put(key, v != null && secret ? MASK : nested(v, null, null, depth + 1));
            });
            return inner;
        }
        List<Object> items = new ArrayList<>();
        for (Object item : (Collection<?>) value) {
            items.add(nested(item, null, null, depth + 1));
        }
        return items;
    }

    /**
     * A free text (an error message for the audit) with secrets taken out: every value
     * the arguments carry in a sensitive place (four characters or more), anything shaped
     * like a JWT or a bearer token, and {@code password=...}-style assignments; at most
     * {@link #MAX_MESSAGE} characters.
     */
    public static String scrub(String text, JsonObject schema, Map<String, Object> args) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String out = text;
        Set<String> secrets = new TreeSet<>(
                Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()));
        collect(args, redact(schema, args), secrets);
        for (String secret : secrets) {
            out = out.replace(secret, MASK);
        }
        out = JWT.matcher(out).replaceAll(MASK);
        out = BEARER.matcher(out).replaceAll("$1" + MASK);
        out = ASSIGNMENT.matcher(out).replaceAll("$1$2" + MASK);
        return out.length() <= MAX_MESSAGE ? out : out.substring(0, MAX_MESSAGE - 1) + "…";
    }

    /** The original values wherever the redacted copy has the mask. */
    private static void collect(Object original, Object redacted, Set<String> into) {
        if (MASK.equals(redacted) && original != null && !MASK.equals(original)) {
            if (original instanceof Map<?, ?> || original instanceof Collection<?>) {
                flatten(original, into);
            }
            else if (String.valueOf(original).length() >= 4) {
                into.add(String.valueOf(original));
            }
            return;
        }
        if (original instanceof JsonObject json) {
            original = json.getMap();
        }
        if (original instanceof Map<?, ?> o && redacted instanceof Map<?, ?> r) {
            o.forEach((k, v) -> collect(v, r.get(String.valueOf(k)), into));
        }
        else if (original instanceof List<?> o && redacted instanceof List<?> r) {
            for (int i = 0; i < Math.min(o.size(), r.size()); i++) {
                collect(o.get(i), r.get(i), into);
            }
        }
    }

    private static void flatten(Object value, Set<String> into) {
        if (value instanceof Map<?, ?> m) {
            m.values().forEach(v -> flatten(v, into));
        }
        else if (value instanceof Collection<?> c) {
            c.forEach(v -> flatten(v, into));
        }
        else if (value != null && String.valueOf(value).length() >= 4) {
            into.add(String.valueOf(value));
        }
    }

    private static JsonObject property(JsonObject schema, String name) {
        JsonObject props = schema == null ? null : schema.getJsonObject("properties");
        return props == null ? null : props.getJsonObject(name);
    }
}
