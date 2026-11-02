package org.keycloak.mcp.spi;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Read-only view on {@code kc-mcp.spi.<id>.*}. Keys are relative and single-segment, e.g. {@code get("page-size")}
 * reads {@code kc-mcp.spi.<id>.page-size} / {@code KC_MCP_SPI_<ID>_PAGE_SIZE}.
 */
public final class ProviderConfig {

    public static final String PREFIX = "kc-mcp.spi.";

    private final String providerId;
    private final Map<String, String> values;

    public ProviderConfig(String providerId, Map<String, String> values) {
        this.providerId = providerId;
        this.values = values == null ? Map.of() : Map.copyOf(values);
    }

    public String providerPrefix() {
        return PREFIX + providerId + ".";
    }

    public Optional<String> get(String key) {
        return Optional.ofNullable(values.get(key)).filter(v -> !v.isBlank());
    }

    public String get(String key, String defaultValue) {
        return get(key).orElse(defaultValue);
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        return get(key).map(v -> v.trim().equalsIgnoreCase("true")).orElse(defaultValue);
    }

    public int getInt(String key, int defaultValue) {
        return get(key).map(v -> Integer.parseInt(v.trim())).orElse(defaultValue);
    }

    public Set<String> keys() {
        return new TreeSet<>(values.keySet());
    }

    public Map<String, String> asMap() {
        return values;
    }
}
