package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKeyGenerator;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

/**
 * Read-only view on {@code kc-mcp.spi.<spi>.<id>.*}. Keys are relative and
 * single-segment, e.g. {@code get("page-size")} reads
 * {@code kc-mcp.spi.<spi>.<id>.page-size} / {@code KC_MCP_SPI_<SPI>_<ID>_PAGE_SIZE}. The
 * id is used in kebab-case, as Keycloak does with its provider ids:
 * {@code acmeTicketChecker} is configured as
 * {@code kc-mcp.spi.access-check.acme-ticket-checker.*} /
 * {@code KC_MCP_SPI_ACCESS_CHECK_ACME_TICKET_CHECKER_*}; see {@link #configId(String)}.
 */
public final class ProviderConfig {

    public static final String PREFIX = "kc-mcp.spi.";

    private static final Pattern CAMEL = Pattern.compile("([a-z0-9])([A-Z])");
    private static final Pattern ACRONYM = Pattern.compile("([A-Z]+)([A-Z][a-z])");
    private static final Pattern SEPARATORS = Pattern.compile("[^a-z0-9]+");

    /** The names of the extension points, the first segment after {@link #PREFIX}. */
    public static final Set<String> SPIS = Set.of(ToolProvider.SPI, PromptProvider.SPI, Confirmer.SPI, AccessCheck.SPI,
            CallerIssuerPolicy.SPI, AuditListener.SPI, AuditScrubber.SPI, ProfileCheck.SPI, PendingApprovalStore.SPI,
            KeycloakSystemRepository.SPI, KeyVault.SPI, SigningKeyGenerator.SPI, UserSessionStore.SPI);

    private final String spi;
    private final String providerId;
    private final Map<String, String> values;

    /** Settings of an extension point's extension. */
    public ProviderConfig(String spi, String providerId, Map<String, String> values) {
        this.spi = spi;
        this.providerId = configId(providerId);
        this.values = values == null ? Map.of() : Map.copyOf(values);
    }

    /** Settings without an extension point, for tests of an extension's own logic. */
    public ProviderConfig(String providerId, Map<String, String> values) {
        this(null, providerId, values);
    }

    /**
     * The settings of an extension; see {@link #forExtension(String, String, Map, Map)}.
     */
    public static ProviderConfig forExtension(Extension extension, Map<String, Map<String, Map<String, String>>> spis) {
        return forExtension(extension.spiName(), extension.id(), spis);
    }

    /** The settings of an extension, with the process environment. */
    public static ProviderConfig forExtension(String spi, String extensionId,
            Map<String, Map<String, Map<String, String>>> spis) {
        return forExtension(spi, extensionId, spis, System.getenv());
    }

    /**
     * The settings of an extension: the {@code kc-mcp.spi} entry under the extension
     * point and the kebab-case id (else the id as written), with environment variables
     * {@code KC_MCP_SPI_<SPI>_<ID>_<KEY>} on top. The variables are read here because the
     * config mapping cannot tell {@code AUTH_FLOWS} from {@code AUTH.FLOWS} in a map key;
     * with extension point and id known, the remainder is the key ({@code _} ->
     * {@code -}, lowercase).
     * @param env the environment to read the variables from
     */
    public static ProviderConfig forExtension(String spi, String extensionId,
            Map<String, Map<String, Map<String, String>>> spis, Map<String, String> env) {
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Map<String, String>> ofSpi = spis == null ? null : spis.get(spi);
        if (ofSpi != null) {
            Map<String, String> entry = ofSpi.get(configId(extensionId));
            if (entry == null) {
                entry = ofSpi.get(extensionId);
            }
            if (entry != null) {
                values.putAll(entry);
            }
        }
        String prefix = new ProviderConfig(spi, extensionId, Map.of()).envPrefix();
        if (env != null) {
            for (Map.Entry<String, String> e : env.entrySet()) {
                if (e.getKey().startsWith(prefix) && e.getKey().length() > prefix.length()) {
                    String key = e.getKey().substring(prefix.length()).toLowerCase(Locale.ROOT).replace('_', '-');
                    values.put(key, e.getValue());
                }
            }
        }
        return new ProviderConfig(spi, extensionId, values);
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

    /** {@code kc-mcp.spi.<spi>.<config id>.} */
    public String providerPrefix() {
        return PREFIX + (spi == null ? "" : spi + ".") + providerId + ".";
    }

    /** {@code KC_MCP_SPI_<SPI>_<CONFIG_ID>_} */
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
