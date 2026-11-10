package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

/**
 * One access check's entry in an {@link AccessSettings} block: whether it runs, where in
 * the order, and its settings. The server's entry comes from
 * {@code kc-mcp.spi.access-check.<id>.*}; a system's and a realm's entry go over it key
 * by key ({@link #overlay}).
 * <p>
 * Settings are flat kebab-case keys; a nested object becomes keys with dots, so the
 * {@code authorization} check's {@code {"authzen": {"url": "..."}}} is
 * {@code authzen.url}. Secret values ({@link #isSensitive}) may be {@code vault:<name>}
 * references.
 *
 * @param enabled whether the check runs; empty: the level below decides
 * @param order where it runs, lower first; empty: the level below decides
 * @param settings the check's own settings
 */
public record CheckSettings(Optional<Boolean> enabled, Optional<Integer> order, Map<String, String> settings) {

    public static final CheckSettings NONE = new CheckSettings(Optional.empty(), Optional.empty(), Map.of());

    static final String ENABLED = "enabled";

    /** The value of a key that stands for an empty nested object. */
    public static final String EMPTY_OBJECT = "{}";
    static final String ORDER = "order";

    public CheckSettings {
        enabled = enabled == null ? Optional.empty() : enabled;
        order = order == null ? Optional.empty() : order;
        Map<String, String> s = new TreeMap<>();
        if (settings != null) {
            settings.forEach((k, v) -> {
                if (k != null && v != null && !v.isBlank()) {
                    s.put(key(k), v.trim());
                }
            });
        }
        settings = Collections.unmodifiableMap(s);
    }

    /**
     * Each segment of a dotted key in kebab-case: {@code authzen.clientAuth} ->
     * {@code authzen.client-auth}.
     */
    static String key(String k) {
        StringBuilder b = new StringBuilder();
        for (String segment : k.trim().split("\\.", -1)) {
            if (!b.isEmpty()) {
                b.append('.');
            }
            b.append(ProviderConfig.configId(segment));
        }
        return b.toString();
    }

    /** Whether a setting's value is a secret, by its last segment. */
    public static boolean isSensitive(String key) {
        String last = key.substring(key.lastIndexOf('.') + 1);
        return AuthorizationSettings.SENSITIVE.contains(last) || Sensitive.byName(last);
    }

    public boolean isEmpty() {
        return enabled.isEmpty() && order.isEmpty() && settings.isEmpty();
    }

    /**
     * This entry with a more specific one over it: its switch, order and settings win.
     */
    public CheckSettings overlay(CheckSettings over) {
        if (over == null || over.isEmpty()) {
            return this;
        }
        Map<String, String> merged = new LinkedHashMap<>(settings);
        merged.putAll(over.settings());
        return new CheckSettings(over.enabled().or(() -> enabled), over.order().or(() -> order), merged);
    }

    public CheckSettings withSettings(Map<String, String> newSettings) {
        return new CheckSettings(enabled, order, newSettings);
    }

    /**
     * The settings under a prefix, without it: {@code under("authzen")} gives
     * {@code url}, ...
     */
    public Map<String, String> under(String prefix) {
        String p = key(prefix) + ".";
        Map<String, String> out = new TreeMap<>();
        settings.forEach((k, v) -> {
            if (k.startsWith(p)) {
                out.put(k.substring(p.length()), v);
            }
        });
        return out;
    }

    /**
     * From flat keys as the configuration gives them: {@code enabled}, {@code order},
     * everything else a setting.
     *
     * @param where the configuration prefix, for error messages
     */
    public static CheckSettings fromFlat(Map<String, String> flat, String where) {
        if (flat == null || flat.isEmpty()) {
            return NONE;
        }
        Optional<Boolean> enabled = Optional.empty();
        Optional<Integer> order = Optional.empty();
        Map<String, String> settings = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : flat.entrySet()) {
            String k = e.getKey().trim();
            String v = e.getValue() == null ? "" : e.getValue().trim();
            switch (k) {
                case ENABLED -> enabled = Optional.of(SettingValues.parseBoolean(v, where + k));
                case ORDER -> order = Optional.of(SettingValues.parseInt(v, where + k));
                default -> settings.put(k, v);
            }
        }
        return new CheckSettings(enabled, order, settings);
    }

    /**
     * From the JSON of the systems file and the admin API: {@code enabled},
     * {@code order}, the check's settings (nested objects allowed).
     *
     * @param where the entry's path, for error messages
     */
    public static CheckSettings fromJson(JsonObject json, String where) {
        if (json == null || json.isEmpty()) {
            return NONE;
        }
        Optional<Boolean> enabled = Optional.empty();
        Optional<Integer> order = Optional.empty();
        Map<String, String> settings = new LinkedHashMap<>();
        for (String field : json.fieldNames()) {
            Object v = json.getValue(field);
            if (ENABLED.equals(field)) {
                if (!(v instanceof Boolean b)) {
                    throw new IllegalArgumentException(where + "enabled must be true or false");
                }
                enabled = Optional.of(b);
            }
            else if (ORDER.equals(field)) {
                if (!(v instanceof Integer i)) {
                    throw new IllegalArgumentException(where + "order must be a whole number");
                }
                order = Optional.of(i);
            }
            else {
                flatten(field, v, where, settings);
            }
        }
        return new CheckSettings(enabled, order, settings);
    }

    private static void flatten(String key, Object v, String where, Map<String, String> out) {
        if (v instanceof JsonObject o && o.isEmpty()) {
            // an empty object still says something: "acme-opa": {} names an engine
            out.put(key, EMPTY_OBJECT);
        }
        else if (v instanceof JsonObject o) {
            for (String inner : o.fieldNames()) {
                flatten(key + "." + inner, o.getValue(inner), where, out);
            }
        }
        else if (v instanceof String || v instanceof Number || v instanceof Boolean) {
            out.put(key, String.valueOf(v));
        }
        else if (v != null) {
            throw new IllegalArgumentException(where + key + " must be a string, number, boolean or object");
        }
    }

    /**
     * The JSON shape: camelCase keys, dotted keys as nested objects.
     *
     * @param masked secret values as {@code ***}, {@code vault:} references as they are
     */
    public Map<String, Object> toMap(boolean masked) {
        Map<String, Object> out = new LinkedHashMap<>();
        enabled.ifPresent(v -> out.put(ENABLED, v));
        order.ifPresent(v -> out.put(ORDER, v));
        settings.forEach((k, v) -> {
            Object value = EMPTY_OBJECT.equals(v) ? new LinkedHashMap<String, Object>()
                    : masked && isSensitive(k) && !KeycloakSystem.isVaultRef(v) ? "***"
                            : SettingValues.coerceBoolean(v);
            put(out, k.split("\\."), 0, value);
        });
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void put(Map<String, Object> into, String[] path, int i, Object value) {
        // leaf keys in camelCase; the names of nested objects (an engine's id) as they
        // are
        String name = i == path.length - 1 ? AuthorizationSettings.camel(path[i]) : path[i];
        if (i == path.length - 1) {
            into.put(name, value);
            return;
        }
        Object child = into.computeIfAbsent(name, n -> new LinkedHashMap<String, Object>());
        if (child instanceof Map<?, ?> m) {
            put((Map<String, Object>) m, path, i + 1, value);
        }
    }

    public JsonObject toJson(boolean masked) {
        return new JsonObject(toMap(masked));
    }

    /** Never prints secret values. */
    @Override
    public String toString() {
        return "CheckSettings" + toJson(true).encode();
    }
}
