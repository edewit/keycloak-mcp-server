package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.vertx.core.json.JsonArray;

/**
 * Parsing of setting values as they come from configuration (strings) and from JSON
 * (systems file, admin API), with errors that name the setting. Shared by the sections of
 * systems, realms and presets.
 */
public final class SettingValues {

    private SettingValues() {
    }

    /**
     * {@code true} or {@code false}, in any case.
     *
     * @param key the setting, for the error message
     * @throws IllegalArgumentException for anything else
     */
    public static boolean parseBoolean(String value, String key) {
        String v = value == null ? "" : value.trim();
        return switch (v.toLowerCase(Locale.ROOT)) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new IllegalArgumentException(key + " must be true or false, not '" + v + "'");
        };
    }

    /**
     * A whole number.
     *
     * @param key the setting, for the error message
     * @throws IllegalArgumentException for anything else
     */
    public static int parseInt(String value, String key) {
        String v = value == null ? "" : value.trim();
        try {
            return Integer.parseInt(v);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException(key + " must be a whole number, not '" + v + "'", e);
        }
    }

    /** A comma separated list: entries trimmed, blank ones dropped. */
    public static List<String> csv(String value) {
        List<String> out = new ArrayList<>();
        if (value == null) {
            return out;
        }
        for (String s : value.split(",")) {
            if (!s.isBlank()) {
                out.add(s.trim());
            }
        }
        return out;
    }

    /**
     * A list of names from JSON: an array of strings, or a comma separated string as in
     * the configuration.
     *
     * @param key the setting, for the error message
     * @throws IllegalArgumentException for anything else
     */
    public static List<String> names(Object value, String key) {
        if (value instanceof String s) {
            return csv(s);
        }
        if (value instanceof JsonArray a) {
            List<String> out = new ArrayList<>();
            for (Object item : a) {
                if (!(item instanceof String s)) {
                    throw new IllegalArgumentException(key + " must list names");
                }
                out.add(s);
            }
            return out;
        }
        throw new IllegalArgumentException(key + " must be a list of names");
    }

    /**
     * A stored string as it was in JSON when it is a boolean: {@code "true"} and
     * {@code "false"} become {@link Boolean}s, everything else stays the string. Settings
     * are kept as strings; this gives a representation its booleans back.
     */
    public static Object coerceBoolean(String value) {
        if ("true".equals(value) || "false".equals(value)) {
            return Boolean.parseBoolean(value);
        }
        return value;
    }
}
