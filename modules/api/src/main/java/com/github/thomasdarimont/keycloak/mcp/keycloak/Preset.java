package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import io.vertx.core.json.JsonObject;

/**
 * A named set of settings, for systems and realms to reference ({@code "preset":
 * "<name>"}) instead of repeating them. It holds the sections systems and realms have
 * that make sense to share: {@code access}, the access checks, and {@code tools}, the
 * tool restrictions. A preset may extend one other preset: the parent's settings first,
 * its own over them ({@link Presets#resolve}).
 * <p>
 * Server presets: {@code kc-mcp.presets.<name>.extends} and
 * {@code kc-mcp.presets.<name>.access.<check>.<key>},
 * {@code kc-mcp.presets.<name>.tools.<key>}. A system's own:
 * {@code kc-mcp.systems.<system>.presets.<name>...}, or {@code "presets": {"<name>":
 * {"extends": "...", "access": {"<check>": {...}}}}} in the systems file and the admin
 * API.
 *
 * @param name the name references use
 * @param parent the preset it extends; empty for none
 * @param access its access section
 * @param tools its tools section
 */
public record Preset(String name, Optional<String> parent, AccessSettings access, ToolSettings tools) {

    static final String EXTENDS = "extends";
    static final String ACCESS = "access";
    static final String TOOLS = "tools";

    public Preset {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("A preset needs a name");
        }
        name = name.trim();
        parent = parent == null ? Optional.empty() : parent.map(String::trim).filter(p -> !p.isEmpty());
        access = access == null ? AccessSettings.NONE : access;
        tools = tools == null ? ToolSettings.NONE : tools;
    }

    /** Only an access section. */
    public Preset(String name, Optional<String> parent, AccessSettings access) {
        this(name, parent, access, ToolSettings.NONE);
    }

    /**
     * From flat keys as the configuration gives them: {@code extends}, and per section
     * its keys, {@code access.<check>.<key>}.
     *
     * @param where the configuration prefix of the preset, for error messages
     */
    public static Preset fromFlat(String name, Map<String, String> flat, String where) {
        Optional<String> parent = Optional.empty();
        Map<String, Map<String, String>> byCheck = new LinkedHashMap<>();
        Map<String, String> toolKeys = new LinkedHashMap<>();
        String access = ACCESS + ".";
        String tools = TOOLS + ".";
        for (Map.Entry<String, String> e : flat.entrySet()) {
            String k = e.getKey().trim();
            if (EXTENDS.equals(k)) {
                parent = Optional.ofNullable(e.getValue());
                continue;
            }
            if (k.startsWith(tools)) {
                toolKeys.put(k.substring(tools.length()), e.getValue());
                continue;
            }
            if (!k.startsWith(access)) {
                throw new IllegalArgumentException(where + k + ": " + unknownSection(k));
            }
            String rest = k.substring(access.length());
            int dot = rest.indexOf('.');
            if (dot <= 0 || dot == rest.length() - 1) {
                throw new IllegalArgumentException(where + k + ": the access section holds access.<check>.<key>");
            }
            byCheck.computeIfAbsent(rest.substring(0, dot), id -> new LinkedHashMap<>())
                .put(rest.substring(dot + 1), e.getValue());
        }
        return new Preset(name, parent, AccessSettings.fromConfig(byCheck, where + access),
                ToolSettings.fromFlat(toolKeys, where + tools));
    }

    /**
     * From the JSON of the systems file and the admin API: {@code {"extends": "...",
     * "access": {...}}}.
     */
    public static Preset fromJson(String name, JsonObject json, String where) {
        JsonObject in = json == null ? new JsonObject() : json;
        Optional<String> parent = Optional.empty();
        AccessSettings accessSettings = AccessSettings.NONE;
        ToolSettings toolSettings = ToolSettings.NONE;
        for (String field : in.fieldNames()) {
            Object v = in.getValue(field);
            switch (field) {
                case EXTENDS -> {
                    if (!(v instanceof String p)) {
                        throw new IllegalArgumentException(where + "extends must be the name of a preset");
                    }
                    parent = Optional.of(p);
                }
                case ACCESS -> {
                    if (!(v instanceof JsonObject o)) {
                        throw new IllegalArgumentException(where + "access must map check ids to their entries");
                    }
                    accessSettings = AccessSettings.fromJson(o, where + "access.");
                }
                case TOOLS -> {
                    if (!(v instanceof JsonObject o)) {
                        throw new IllegalArgumentException(where + "tools must be an object");
                    }
                    toolSettings = ToolSettings.fromJson(o, where + "tools.");
                }
                default -> throw new IllegalArgumentException(where + field + ": " + unknownSection(field));
            }
        }
        return new Preset(name, parent, accessSettings, toolSettings);
    }

    /** The sections a preset can hold: those systems and realms have. */
    static final java.util.Set<String> SECTIONS = new java.util.TreeSet<>(java.util.List.of(ACCESS, TOOLS));

    private static String unknownSection(String key) {
        String section = key.contains(".") ? key.substring(0, key.indexOf('.')) : key;
        return "'" + section + "' is not a section of a preset; a preset holds extends and " + SECTIONS
                + " (an access check's entry goes under access.<check>)";
    }

    /**
     * The JSON shape.
     *
     * @param masked secret values as {@code ***}
     */
    public Map<String, Object> toMap(boolean masked) {
        Map<String, Object> out = new LinkedHashMap<>();
        parent.ifPresent(p -> out.put(EXTENDS, p));
        if (!access.isEmpty()) {
            out.put(ACCESS, access.toMap(masked));
        }
        if (!tools.isEmpty()) {
            out.put(TOOLS, tools.toMap());
        }
        return out;
    }
}
