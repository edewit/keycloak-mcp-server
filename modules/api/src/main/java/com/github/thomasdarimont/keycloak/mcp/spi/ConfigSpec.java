package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * How an extension is configured ({@link Extension#configSpec()}): its settings
 * ({@link ConfigProperty}) and how they belong together ({@link ConfigHint}). Data only,
 * for startup checks, the admin API, a generic UI and the documentation; rules that need
 * code are {@link Extension#validate}'s.
 *
 * @param properties the settings, in the order to show them; names unique
 * @param hints sections and conditions; they name declared settings only (a condition may
 * also depend on a setting the server handles, such as {@code enabled})
 */
public record ConfigSpec(List<ConfigProperty> properties, List<ConfigHint> hints) {

    /** Nothing declared: nothing is checked. */
    public static final ConfigSpec EMPTY = new ConfigSpec(List.of(), List.of());

    public ConfigSpec {
        properties = properties == null ? List.of() : List.copyOf(properties);
        hints = hints == null ? List.of() : List.copyOf(hints);
        Map<String, ConfigProperty> byName = new LinkedHashMap<>();
        for (ConfigProperty p : properties) {
            if (byName.putIfAbsent(p.name(), p) != null) {
                throw new IllegalArgumentException("'" + p.name() + "' is declared twice");
            }
        }
        for (ConfigHint h : hints) {
            for (String name : h.properties()) {
                if (!byName.containsKey(name)) {
                    throw new IllegalArgumentException("A hint names '" + name + "', which is not declared");
                }
            }
            if (h instanceof ConfigHint.AppliesWhen w && !byName.containsKey(w.on()) && !serverKey(w.on())) {
                throw new IllegalArgumentException(
                        "'" + w.property() + "' depends on '" + w.on() + "', which is not declared");
            }
        }
    }

    private static boolean serverKey(String key) {
        return ProviderConfig.RESERVED_KEYS.contains(key) || ProviderConfig.ACCESS_CHECK_KEYS.contains(key);
    }

    public static ConfigSpec of(ConfigProperty... properties) {
        return new ConfigSpec(Arrays.asList(properties), List.of());
    }

    public static ConfigSpec of(List<ConfigProperty> properties) {
        return new ConfigSpec(properties, List.of());
    }

    /** This spec with further hints. */
    public ConfigSpec withHints(ConfigHint... more) {
        List<ConfigHint> all = new ArrayList<>(hints);
        all.addAll(Arrays.asList(more));
        return new ConfigSpec(properties, all);
    }

    /**
     * This spec and another one, for an extension that reads another component's settings
     * with its own (the client authentication methods' with the AuthZEN engine's): a name
     * declared here wins, the other's hints come along.
     */
    public ConfigSpec plus(ConfigSpec other) {
        if (other == null || other.isEmpty()) {
            return this;
        }
        Map<String, ConfigProperty> byName = new LinkedHashMap<>();
        properties.forEach(p -> byName.put(p.name(), p));
        other.properties().forEach(p -> byName.putIfAbsent(p.name(), p));
        List<ConfigHint> all = new ArrayList<>(hints);
        other.hints().stream().filter(h -> !all.contains(h)).forEach(all::add);
        return new ConfigSpec(List.copyOf(byName.values()), all);
    }

    public boolean isEmpty() {
        return properties.isEmpty() && hints.isEmpty();
    }

    public Optional<ConfigProperty> property(String name) {
        return properties.stream().filter(p -> p.name().equals(name)).findFirst();
    }

    /** The conditions of a setting; empty when it always applies. */
    public List<ConfigHint.AppliesWhen> conditions(String name) {
        return hints.stream()
            .filter(ConfigHint.AppliesWhen.class::isInstance)
            .map(ConfigHint.AppliesWhen.class::cast)
            .filter(w -> w.property().equals(name))
            .toList();
    }

    /** The declared names. */
    public Set<String> names() {
        Set<String> names = new java.util.LinkedHashSet<>();
        properties.forEach(p -> names.add(p.name()));
        return names;
    }
}
