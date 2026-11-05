package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Read-only view on {@code kc-mcp.spi.<id>.*}. Keys are relative and single-segment, e.g.
 * {@code get("page-size")} reads {@code kc-mcp.spi.<id>.page-size} /
 * {@code KC_MCP_SPI_<ID>_PAGE_SIZE}. The id is used in kebab-case, as Keycloak does with
 * its provider ids: {@code acmeTicketChecker} is configured as
 * {@code kc-mcp.spi.acme-ticket-checker.*} / {@code KC_MCP_SPI_ACME_TICKET_CHECKER_*};
 * see {@link #configId(String)}.
 */
public final class ProviderConfig {

    public static final String PREFIX = "kc-mcp.spi.";

    private static final Pattern CAMEL = Pattern.compile("([a-z0-9])([A-Z])");
    private static final Pattern ACRONYM = Pattern.compile("([A-Z]+)([A-Z][a-z])");
    private static final Pattern SEPARATORS = Pattern.compile("[^a-z0-9]+");

    private final String providerId;
    private final Map<String, String> values;

    public ProviderConfig(String providerId, Map<String, String> values) {
        this.providerId = configId(providerId);
        this.values = values == null ? Map.of() : Map.copyOf(values);
    }

    /**
     * The settings of an extension: the {@code kc-mcp.spi} map entry under the kebab-case
     * id (else under the id as written), with environment variables
     * {@code KC_MCP_SPI_<ID>_<KEY>} on top. The variables are read here because the
     * config mapping cannot tell {@code AUTH_FLOWS} from {@code AUTH.FLOWS} in a map key;
     * with the id known, the remainder is the key ({@code _} -> {@code -}, lowercase).
     */
    public static ProviderConfig forExtension(String extensionId, Map<String, Map<String, String>> spi) {
        return forExtension(extensionId, spi, System.getenv());
    }

    /** @param env the environment to read {@code KC_MCP_SPI_<ID>_<KEY>} from */
    public static ProviderConfig forExtension(String extensionId, Map<String, Map<String, String>> spi,
            Map<String, String> env) {
        Map<String, String> values = new LinkedHashMap<>();
        if (spi != null) {
            Map<String, String> entry = spi.get(configId(extensionId));
            if (entry == null) {
                entry = spi.get(extensionId);
            }
            if (entry != null) {
                values.putAll(entry);
            }
        }
        String prefix = new ProviderConfig(extensionId, Map.of()).envPrefix();
        if (env != null) {
            for (Map.Entry<String, String> e : env.entrySet()) {
                if (e.getKey().startsWith(prefix) && e.getKey().length() > prefix.length()) {
                    String key = e.getKey().substring(prefix.length()).toLowerCase(Locale.ROOT).replace('_', '-');
                    values.put(key, e.getValue());
                }
            }
        }
        return new ProviderConfig(extensionId, values);
    }

    /**
     * The id as it appears in configuration keys: camelCase split at the humps, every run
     * of other separators ({@code .}, {@code _}, {@code $}, blanks) a single {@code -},
     * all lowercase. {@code acmeTicketChecker} and {@code acme_ticket_checker} both give
     * {@code acme-ticket-checker}; the class-name default id
     * {@code com.acme.TicketChecker} gives {@code com-acme-ticket-checker}.
     */
    public static String configId(String id) {
        String s = ACRONYM.matcher(id.trim()).replaceAll("$1-$2");
        s = CAMEL.matcher(s).replaceAll("$1-$2").toLowerCase(Locale.ROOT);
        s = SEPARATORS.matcher(s).replaceAll("-");
        return s.replaceAll("^-+|-+$", "");
    }

    /** {@code kc-mcp.spi.<config id>.} */
    public String providerPrefix() {
        return PREFIX + providerId + ".";
    }

    /** {@code KC_MCP_SPI_<CONFIG_ID>_} */
    public String envPrefix() {
        return providerPrefix().toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
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
