package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

/**
 * Which access checks govern a Keycloak system or one of its realms, in which order and
 * with which settings: an entry per check id ({@link CheckSettings}) over the server's
 * {@code kc-mcp.spi.access-check.<id>.*}. A realm's block goes over its system's
 * ({@link #overlay}), entry by entry and key by key.
 * <p>
 * Configuration {@code kc-mcp.systems.<name>.access.<check>.<key>} (and
 * {@code ...realms.<realm>.access...}), systems file and admin API {@code "access":
 * {"self-protection": {"order": 10, "mode": "confirm"}, "group-scope": {"enabled":
 * false}}}. A check the operator locked
 * ({@code kc-mcp.spi.access-check.<id>.locked=true}) takes no entry here; an entry for a
 * check the server does not have denies the calls it would govern.
 *
 * @param checks entries by check id (kebab-case)
 */
public record AccessSettings(Map<String, CheckSettings> checks) {

    public static final AccessSettings NONE = new AccessSettings(Map.of());

    public AccessSettings {
        Map<String, CheckSettings> c = new TreeMap<>();
        if (checks != null) {
            checks.forEach((id, s) -> {
                if (id != null && !id.isBlank() && s != null && !s.isEmpty()) {
                    c.put(ProviderConfig.configId(id), s);
                }
            });
        }
        checks = Collections.unmodifiableMap(c);
    }

    public boolean isEmpty() {
        return checks.isEmpty();
    }

    /** The entry of a check; {@link CheckSettings#NONE} when the block has none. */
    public CheckSettings check(String id) {
        return checks.getOrDefault(ProviderConfig.configId(id), CheckSettings.NONE);
    }

    /** A copy with one check's entry replaced ({@link CheckSettings#NONE} removes it). */
    public AccessSettings with(String id, CheckSettings entry) {
        Map<String, CheckSettings> c = new LinkedHashMap<>(checks);
        c.put(ProviderConfig.configId(id), entry);
        return new AccessSettings(c);
    }

    /** This block with a more specific one over it, entry by entry. */
    public AccessSettings overlay(AccessSettings over) {
        if (over == null || over.isEmpty()) {
            return this;
        }
        Map<String, CheckSettings> merged = new LinkedHashMap<>(checks);
        over.checks().forEach((id, entry) -> merged.merge(id, entry, CheckSettings::overlay));
        return new AccessSettings(merged);
    }

    /**
     * From {@code kc-mcp.systems.<name>.access.<check>.<key>}.
     *
     * @param where the configuration prefix up to {@code access.}
     */
    public static AccessSettings fromConfig(Map<String, Map<String, String>> byCheck, String where) {
        if (byCheck == null || byCheck.isEmpty()) {
            return NONE;
        }
        Map<String, CheckSettings> out = new LinkedHashMap<>();
        byCheck.forEach((id, flat) -> out.put(id, CheckSettings.fromFlat(flat, where + id + ".")));
        return new AccessSettings(out);
    }

    /** From the JSON of the systems file and the admin API. */
    public static AccessSettings fromJson(JsonObject json, String where) {
        if (json == null || json.isEmpty()) {
            return NONE;
        }
        Map<String, CheckSettings> out = new LinkedHashMap<>();
        for (String id : json.fieldNames()) {
            Object v = json.getValue(id);
            if (!(v instanceof JsonObject entry)) {
                throw new IllegalArgumentException(
                        where + id + " must be an object: {\"enabled\": ..., \"order\": ..., <the check's settings>}");
            }
            out.put(id, CheckSettings.fromJson(entry, where + id + "."));
        }
        return new AccessSettings(out);
    }

    /**
     * The JSON shape.
     *
     * @param masked secret values as {@code ***}
     */
    public Map<String, Object> toMap(boolean masked) {
        Map<String, Object> out = new LinkedHashMap<>();
        checks.forEach((id, entry) -> out.put(id, entry.toMap(masked)));
        return out;
    }

    public JsonObject toJson(boolean masked) {
        return new JsonObject(toMap(masked));
    }

    @Override
    public String toString() {
        return "AccessSettings" + toJson(true).encode();
    }
}
