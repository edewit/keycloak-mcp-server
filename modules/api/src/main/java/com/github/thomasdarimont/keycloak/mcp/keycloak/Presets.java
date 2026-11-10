package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The presets a system can reference: its own, then the server's. Resolving a name walks
 * its {@code extends} chain, parent first, each preset's entries over its parent's; a
 * preset met twice on the way is a cycle and an error, and so is a chain deeper than
 * {@link #MAX_DEPTH}. A system preset may extend a server preset, never the other way
 * round: server presets only see each other.
 */
public final class Presets {

    /** How many presets one chain may hold. */
    public static final int MAX_DEPTH = 16;

    public static final Presets NONE = new Presets(Map.of());

    private final Map<String, Preset> server;

    public Presets(Map<String, Preset> server) {
        this.server = Collections.unmodifiableMap(new LinkedHashMap<>(server == null ? Map.of() : server));
    }

    /**
     * The server's presets from {@code kc-mcp.presets.<name>.*}.
     *
     * @throws IllegalArgumentException for a preset that does not parse
     */
    public static Presets fromConfig(Map<String, Map<String, String>> byName) {
        Map<String, Preset> out = new LinkedHashMap<>();
        if (byName != null) {
            byName.forEach((name, flat) -> out.put(name, Preset.fromFlat(name, flat, "kc-mcp.presets." + name + ".")));
        }
        return new Presets(out);
    }

    /** The id of the entry that stands for a preset reference that does not resolve. */
    public static final String UNRESOLVED = "unresolved-preset";

    /**
     * {@link #apply}, or, when the references do not resolve, the system with an entry
     * for a check no server has ({@link #UNRESOLVED}), so that its calls are denied
     * rather than run without the preset.
     */
    public KeycloakSystem applyOrBlock(KeycloakSystem system, java.util.function.Consumer<String> problem) {
        try {
            return apply(system);
        }
        catch (IllegalArgumentException e) {
            problem.accept(e.getMessage());
            CheckSettings blocked = new CheckSettings(Optional.of(true), Optional.empty(), Map.of());
            Map<String, RealmSettings> realms = new LinkedHashMap<>();
            system.realms().forEach((n, r) -> realms.put(n, r.withAccess(r.access().with(UNRESOLVED, blocked))));
            return system.toBuilder().access(system.access().with(UNRESOLVED, blocked)).realms(realms.values()).build();
        }
    }

    public Map<String, Preset> server() {
        return server;
    }

    /**
     * The entries of a preset, its ancestors' with its own over them.
     *
     * @param own the system's own presets, looked up first; empty for server presets
     * @throws IllegalArgumentException for an unknown name, a cycle or a chain too deep;
     * the message names the chain
     */
    public AccessSettings resolve(String name, Map<String, Preset> own) {
        List<Preset> chain = chain(name, own);
        AccessSettings out = AccessSettings.NONE;
        for (int i = chain.size() - 1; i >= 0; i--) {
            out = out.overlay(chain.get(i).access());
        }
        return out;
    }

    /** The preset and its ancestors, the preset first. */
    public List<Preset> chain(String name, Map<String, Preset> own) {
        Map<String, Preset> local = own == null ? Map.of() : own;
        List<Preset> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        String next = name;
        // a preset the system defines is looked up there and then on the server; once on
        // the server, the chain stays there
        boolean onServer = false;
        while (next != null) {
            String key = (onServer ? "server:" : "") + next;
            if (!seen.add(key)) {
                throw new IllegalArgumentException(
                        "The presets form a cycle: " + String.join(" -> ", names(out)) + " -> " + next);
            }
            if (out.size() >= MAX_DEPTH) {
                throw new IllegalArgumentException("The preset '" + name + "' extends more than " + MAX_DEPTH
                        + " presets: " + String.join(" -> ", names(out)));
            }
            Preset p = onServer ? null : local.get(next);
            if (p == null) {
                p = server.get(next);
                onServer = true;
            }
            if (p == null) {
                throw new IllegalArgumentException("No preset named '" + next + "'"
                        + (out.isEmpty() ? "" : " (extended by '" + out.getLast().name() + "')") + "; known: "
                        + known(local));
            }
            out.add(p);
            next = p.parent().orElse(null);
        }
        return out;
    }

    /** Every preset of a system and of the server resolves: names exist, no cycles. */
    public void validate(Map<String, Preset> own) {
        for (String name : server.keySet()) {
            resolve(name, Map.of());
        }
        if (own != null) {
            for (String name : own.keySet()) {
                resolve(name, own);
            }
        }
    }

    private Set<String> known(Map<String, Preset> local) {
        Set<String> out = new LinkedHashSet<>(local.keySet());
        out.addAll(server.keySet());
        return out;
    }

    private static List<String> names(List<Preset> chain) {
        return chain.stream().map(Preset::name).toList();
    }

    /**
     * A system with its preset references resolved into its access blocks: the system's
     * block is its preset's entries with its own over them, a realm's likewise, so that
     * {@link KeycloakSystem#access(String)} and {@link KeycloakSystem#tools(String)} give
     * preset < system < realm preset < realm.
     *
     * @throws IllegalArgumentException when a reference does not resolve
     */
    public KeycloakSystem apply(KeycloakSystem system) {
        if (system.preset().isEmpty() && system.realms().values().stream().allMatch(r -> r.preset().isEmpty())) {
            return system;
        }
        Map<String, Preset> own = system.presets();
        KeycloakSystem.Builder b = system.toBuilder();
        system.preset().ifPresent(p -> {
            Resolved r = resolveAll(p, own);
            b.access(r.access().overlay(system.access())).tools(r.tools().overlay(system.tools()));
        });
        Map<String, RealmSettings> realms = new LinkedHashMap<>();
        system.realms().forEach((name, realm) -> realms.put(name, realm.preset().map(p -> {
            Resolved r = resolveAll(p, own);
            return realm.withAccess(r.access().overlay(realm.access())).withTools(r.tools().overlay(realm.tools()));
        }).orElse(realm)));
        return b.realms(realms.values()).build();
    }

    /** A preset's sections, its ancestors' with its own over them. */
    public record Resolved(AccessSettings access, ToolSettings tools) {
    }

    /** {@link #resolve} for every section. */
    public Resolved resolveAll(String name, Map<String, Preset> own) {
        List<Preset> chain = chain(name, own);
        AccessSettings access = AccessSettings.NONE;
        ToolSettings tools = ToolSettings.NONE;
        for (int i = chain.size() - 1; i >= 0; i--) {
            access = access.overlay(chain.get(i).access());
            tools = tools.overlay(chain.get(i).tools());
        }
        return new Resolved(access, tools);
    }

    /** Whether a preset of that name is known to a system. */
    public boolean knows(String name, Map<String, Preset> own) {
        return (own != null && own.containsKey(name)) || server.containsKey(name);
    }

    public Optional<Preset> serverPreset(String name) {
        return Optional.ofNullable(server.get(name));
    }
}
