package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

/**
 * The external authorization of a Keycloak system or of one of its realms: whether tool
 * calls are evaluated by an authorization engine, and per engine the settings that differ
 * from that engine's defaults. An engine ({@code AuthorizationEngine}) is a client of an
 * outside policy service; its block is named by the engine's id: {@code authzen} for the
 * built-in AuthZEN engine, an extension's own id for a vendor's engine. The server's
 * access check {@code authorization} hands the calls to the engines.
 * <p>
 * A realm's block overlays its system's ({@link #overlay}): the realm's switch wins, its
 * engine settings win key by key. Which engines evaluate a call: those the effective
 * block names; when it names none, every engine switched on server-wide
 * ({@link #usesEngine}). Whether they do: the effective switch, else the engine's own
 * default ({@link #evaluates}). A block that names an engine the server does not have
 * gets its calls denied.
 * <p>
 * Three shapes, one meaning:
 * <ul>
 * <li>configuration: {@code kc-mcp.systems.<name>.authorization.enabled=true},
 * {@code ...authorization.authzen.url=...}, a realm's
 * {@code kc-mcp.systems.<name>.realms.<realm>.authorization.enabled=false} (kebab-case
 * keys)</li>
 * <li>systems file and admin API: {@code "authorization": {"enabled": true, "authzen":
 * {"url": "...", "clientAuth": "private_key_jwt"}}} (camelCase as the rest of the system;
 * kebab-case is accepted too)</li>
 * <li>here: {@link #engines()} by kebab-case engine id, their settings by kebab-case key,
 * as the engines read them</li>
 * </ul>
 * Secret values ({@link #isSensitive}) may be {@code vault:<name>} references.
 *
 * @param enabled whether calls are evaluated; empty: the system's switch (for a realm),
 * else each engine's default
 * @param engines per engine id its settings by kebab-case key
 */
public record AuthorizationSettings(Optional<Boolean> enabled, Map<String, Map<String, String>> engines) {

    public static final AuthorizationSettings NONE = new AuthorizationSettings(Optional.empty(), Map.of());

    /**
     * Settings whose values are secrets though their names do not say so; besides them,
     * every name that ends like a secret ({@link Sensitive#byName}): masked in
     * representations, encrypted at rest with the rest of the block.
     */
    public static final Set<String> SENSITIVE = Set.of("header-value");

    static final String ENABLED = "enabled";

    public AuthorizationSettings {
        enabled = enabled == null ? Optional.empty() : enabled;
        Map<String, Map<String, String>> e = new TreeMap<>();
        if (engines != null) {
            engines.forEach((id, settings) -> {
                if (id != null && !id.isBlank()) {
                    e.put(ProviderConfig.configId(id), clean(settings));
                }
            });
        }
        engines = Collections.unmodifiableMap(e);
    }

    private static Map<String, String> clean(Map<String, String> settings) {
        Map<String, String> s = new TreeMap<>();
        if (settings != null) {
            settings.forEach((k, v) -> {
                if (k != null && v != null && !v.isBlank()) {
                    s.put(ProviderConfig.configId(k), v.trim());
                }
            });
        }
        return Collections.unmodifiableMap(s);
    }

    /** Whether a setting's value is a secret. */
    public static boolean isSensitive(String key) {
        return SENSITIVE.contains(key) || Sensitive.byName(key);
    }

    public boolean isEmpty() {
        return enabled.isEmpty() && engines.isEmpty();
    }

    /** The settings of an engine by its id; empty when the system has no block for it. */
    public Map<String, String> engine(String id) {
        return engines.getOrDefault(ProviderConfig.configId(id), Map.of());
    }

    /**
     * Whether the engine evaluates this system's calls at all: the system names it, or
     * names no engine.
     */
    public boolean usesEngine(String id) {
        return engines.isEmpty() || engines.containsKey(ProviderConfig.configId(id));
    }

    /**
     * Whether calls are evaluated: the switch, else {@code fallback} (the engine's
     * default).
     */
    public boolean evaluates(boolean fallback) {
        return enabled.orElse(fallback);
    }

    /**
     * {@link #usesEngine} and {@link #evaluates}: what an engine asks of the effective
     * block of a call before it looks at the call.
     */
    public boolean evaluatedBy(String engine, boolean fallback) {
        return usesEngine(engine) && evaluates(fallback);
    }

    /**
     * This block with a realm's on top: the realm's switch when it has one, the engines
     * of both, a realm's engine setting over the system's.
     */
    public AuthorizationSettings overlay(AuthorizationSettings realm) {
        if (realm == null || realm.isEmpty()) {
            return this;
        }
        Map<String, Map<String, String>> merged = new LinkedHashMap<>();
        engines.forEach((id, settings) -> merged.put(id, new LinkedHashMap<>(settings)));
        realm.engines()
            .forEach((id, settings) -> merged.computeIfAbsent(id, k -> new LinkedHashMap<>()).putAll(settings));
        return new AuthorizationSettings(realm.enabled().or(() -> enabled), merged);
    }

    /** A copy with other engine settings, e.g. secret references resolved. */
    public AuthorizationSettings withEngines(Map<String, Map<String, String>> newEngines) {
        return new AuthorizationSettings(enabled, newEngines);
    }

    /** The id of the access check whose entry this is a view of. */
    public static final String CHECK = "authorization";

    /**
     * The view of the {@code authorization} check's entry: its switch, and its settings
     * grouped by engine ({@code authzen.url} is engine {@code authzen}, key {@code url});
     * keys outside an engine are not part of it.
     */
    public static AuthorizationSettings of(CheckSettings entry) {
        if (entry == null || entry.isEmpty()) {
            return NONE;
        }
        Map<String, Map<String, String>> engines = new LinkedHashMap<>();
        entry.settings().forEach((k, v) -> {
            int dot = k.indexOf('.');
            if (dot > 0 && dot < k.length() - 1) {
                engines.computeIfAbsent(k.substring(0, dot), id -> new LinkedHashMap<>()).put(k.substring(dot + 1), v);
            }
            else if (dot < 0 && CheckSettings.EMPTY_OBJECT.equals(v)) {
                engines.computeIfAbsent(k, id -> new LinkedHashMap<>());
            }
        });
        return new AuthorizationSettings(entry.enabled(), engines);
    }

    /** Keys of an entry that belong to no engine, which the check refuses. */
    public static java.util.List<String> strayKeys(CheckSettings entry) {
        return entry.settings()
            .entrySet()
            .stream()
            .filter(e -> e.getKey().indexOf('.') <= 0 && !CheckSettings.EMPTY_OBJECT.equals(e.getValue()))
            .map(Map.Entry::getKey)
            .toList();
    }

    /** Back to the check's entry (no order of its own). */
    public CheckSettings toCheckSettings() {
        Map<String, String> flat = new LinkedHashMap<>();
        engines.forEach((id, settings) -> {
            if (settings.isEmpty()) {
                flat.put(id, CheckSettings.EMPTY_OBJECT);
            }
            settings.forEach((k, v) -> flat.put(id + "." + k, v));
        });
        return new CheckSettings(enabled, Optional.empty(), flat);
    }

    /**
     * From flat kebab-case keys, as the configuration gives them: {@code enabled},
     * {@code <engine>.<setting>}.
     */
    public static AuthorizationSettings fromFlat(Map<String, String> flat) {
        CheckSettings entry = CheckSettings.fromFlat(flat, "authorization.");
        refuseStray(entry);
        return of(entry);
    }

    /**
     * From the JSON of the {@code authorization} entry:
     * {@code {"enabled": ..., "<engine>":
     * {...}}}.
     *
     * @throws IllegalArgumentException for a misplaced or malformed entry
     */
    public static AuthorizationSettings fromJson(JsonObject json) {
        CheckSettings entry = CheckSettings.fromJson(json, "authorization.");
        refuseStray(entry);
        return of(entry);
    }

    private static void refuseStray(CheckSettings entry) {
        for (String k : strayKeys(entry)) {
            throw new IllegalArgumentException("authorization." + k + " belongs to an engine: authorization.<engine>."
                    + k + " (e.g. authorization.authzen." + k + ")");
        }
    }

    /**
     * The JSON shape, camelCase keys (engine ids stay as they are).
     *
     * @param masked secret values as {@code ***}, {@code vault:} references as they are
     */
    public JsonObject toJson(boolean masked) {
        return new JsonObject(toMap(masked));
    }

    /** {@link #toJson} as plain maps, for representations serialized elsewhere. */
    public Map<String, Object> toMap(boolean masked) {
        return toCheckSettings().toMap(masked);
    }

    /** {@code client-secret} -> {@code clientSecret}. */
    public static String camel(String kebab) {
        StringBuilder b = new StringBuilder();
        boolean up = false;
        for (char c : kebab.toCharArray()) {
            if (c == '-') {
                up = true;
            }
            else {
                b.append(up ? Character.toUpperCase(c) : c);
                up = false;
            }
        }
        return b.toString();
    }

    /** Never prints secret values. */
    @Override
    public String toString() {
        return "AuthorizationSettings" + toJson(true).encode();
    }
}
