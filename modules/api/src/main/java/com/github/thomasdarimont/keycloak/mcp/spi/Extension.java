package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

/**
 * What every extension point shares: {@link ToolProvider}, {@link PromptProvider},
 * {@link AccessCheck}, {@link Confirmer} and {@link AuditListener} are extensions. Its
 * type and id key the configuration ({@code kc-mcp.spi.<spi>.<id>.*},
 * {@code enabled=false} switches the extension off) and must be unique per type; the
 * order decides the sequence in which extensions of one type run or are initialised.
 * <p>
 * Lifecycle: one instance per server, shared by all requests, so implementations must be
 * thread-safe. At startup, once: {@link #configure}, then {@link #isSupported}. At
 * shutdown, once and only if it took part: {@link #close}. Settings kept in fields by
 * {@code configure} are safe to read on request threads afterwards.
 */
public interface Extension {

    /**
     * The extension point's name in configuration keys, set by each extension point:
     * {@code confirmer} in {@code kc-mcp.spi.confirmer.<id>.*}.
     */
    String spiName();

    /**
     * Unique, stable id such as {@code users} or {@code acme-tickets}. Configuration keys
     * use it in kebab-case ({@code acmeTickets} ->
     * {@code kc-mcp.spi.tools.acme-tickets.*}, see {@link ProviderConfig#configId}).
     * Defaults to the class name.
     */
    default String id() {
        return getClass().getName();
    }

    /** Human readable name, e.g. "User management". Defaults to the id. */
    default String displayName() {
        return id();
    }

    /** One or two sentences on what the extension does. */
    default String description() {
        return "";
    }

    /** Lower first; ties are broken by id. */
    default int order() {
        return 0;
    }

    /**
     * The settings this extension reads, {@code kc-mcp.spi.<spi>.<id>.<name>}: the server
     * checks them at startup before {@link #configure} (a malformed value or a missing
     * required one counts as a failing {@code configure}, unknown keys are logged), maps
     * environment variables to the declared names, masks the confidential ones and shows
     * them in the admin API. {@code enabled} and {@code required} are the server's
     * ({@link ProviderConfig#RESERVED_KEYS}) and not declared here.
     * <p>
     * Called before {@link #configure}, possibly on an instance that will not be
     * configured, so return constants: a {@code static final} list on the class. Empty
     * (the default) means undeclared: nothing is checked.
     */
    default List<ConfigProperty> configProperties() {
        return List.of();
    }

    /**
     * Hands the extension its own settings, {@code kc-mcp.spi.<spi>.<id>.*} from the
     * configuration files, the environment and the command line, once at startup after
     * the {@code enabled} switch and before {@link #isSupported}. Every extension point
     * gets this call. Only the settings: the Keycloak systems depend on some extensions
     * and do not exist yet. An exception counts as for {@link #isSupported}.
     *
     * @param config this extension's own settings
     */
    default void configure(ProviderConfig config) {
    }

    /**
     * Whether this extension can work with the current configuration, asked once at
     * startup after the {@code enabled} switch: an extension that needs a setting,
     * another extension's feature or a Quarkus capability answers {@code false} when it
     * is missing and is then left out as if it were not on the class path (logged, not
     * fatal), instead of failing on first use. To refuse the start instead, contribute a
     * {@link com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck}. An exception
     * counts as {@code false}.
     *
     * @param serverConfig the server's configuration
     * @param config this extension's own settings, {@code kc-mcp.spi.<spi>.<id>.*}
     */
    default boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
        return true;
    }

    /**
     * Releases what the extension holds (connections, file handles, threads), once when
     * the server shuts down, for extensions that took part. Extensions close in the
     * reverse of the order they were admitted; a failure is logged and the others still
     * close.
     */
    default void close() {
    }
}
