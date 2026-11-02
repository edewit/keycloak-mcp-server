package org.keycloak.mcp.catalog;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.spi.ToolProviderRegistry;

import io.vertx.core.json.JsonObject;

/**
 * All tool specs, keyed by name, with the effective (realm + pagination decorated) input schema.
 */
@ApplicationScoped
public class ToolCatalog {

    private final Map<String, ToolSpec> specs;
    private final String defaultRealm;

    @Inject
    public ToolCatalog(ToolProviderRegistry providers, McpServerConfig config) {
        this(providers.specs(), config.defaultRealm().orElse(null), config.resultMaxItems(), config.hotTools());
    }

    public ToolCatalog(Collection<ToolSpec> raw, String defaultRealm, int maxItems, List<String> hotTools) {
        this.defaultRealm = defaultRealm;
        Set<String> hot = Set.copyOf(hotTools == null ? List.of() : hotTools);
        Map<String, ToolSpec> map = new LinkedHashMap<>();
        List<ToolSpec> sorted = new ArrayList<>(raw);
        sorted.sort(Comparator.comparing(ToolSpec::name));
        for (ToolSpec spec : sorted) {
            if (map.containsKey(spec.name())) {
                throw new IllegalStateException("Duplicate tool name: " + spec.name());
            }
            JsonObject schema = spec.inputSchema();
            if (spec.realmScoped()) {
                schema = InputSchema.withRealm(schema, defaultRealm == null, defaultRealm);
            }
            schema = InputSchema.withMaxItems(schema, maxItems);
            ToolSpec effective = spec.withInputSchema(schema);
            if (!hot.isEmpty()) {
                effective = effective.withHot(hot.contains(spec.name()));
            }
            map.put(spec.name(), effective);
        }
        this.specs = Map.copyOf(map);
    }

    public Collection<ToolSpec> all() {
        return specs.values();
    }

    public int size() {
        return specs.size();
    }

    public Optional<ToolSpec> get(String name) {
        return Optional.ofNullable(specs.get(name));
    }

    /**
     * Forgiving lookup: exact, then case-insensitive with {@code -} normalised to {@code _}, then with the
     * {@code keycloak_} prefix added or removed.
     */
    public Optional<ToolSpec> resolve(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        ToolSpec exact = specs.get(name);
        if (exact != null) {
            return Optional.of(exact);
        }
        String norm = normalize(name);
        List<String> candidates = List.of(norm, "keycloak_" + norm, norm.startsWith("keycloak_") ? norm.substring(9) : norm,
                norm.startsWith("kc_") ? "keycloak_" + norm.substring(3) : norm);
        for (String c : candidates) {
            ToolSpec s = specs.get(c);
            if (s != null) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    public static String normalize(String name) {
        return name.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace('.', '_').replace(' ', '_');
    }

    public String defaultRealm() {
        return defaultRealm;
    }

    public List<ToolSpec> byCategory(Category category) {
        return specs.values().stream().filter(s -> s.category() == category).toList();
    }
}
