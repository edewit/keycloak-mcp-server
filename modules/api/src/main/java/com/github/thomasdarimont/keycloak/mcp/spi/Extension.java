package com.github.thomasdarimont.keycloak.mcp.spi;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

/**
 * What every extension point shares: {@link ToolProvider}, {@link PromptProvider},
 * {@link AccessCheck}, {@link Confirmer} and {@link AuditListener} are extensions. The id
 * keys the configuration ({@code kc-mcp.spi.<id>.*}, {@code enabled=false} switches the
 * extension off) and must be unique per type; the order decides the sequence in which
 * extensions of one type run or are initialised.
 * <p>
 * Lifecycle: one instance per server, shared by all requests, so implementations must be
 * thread-safe. At startup, once: {@link #configure}, then {@link #isSupported}. At
 * shutdown, once and only if it took part: {@link #close}. Settings kept in fields by
 * {@code configure} are safe to read on request threads afterwards.
 */
public interface Extension {

    /**
     * Unique, stable id such as {@code users} or {@code acme-tickets}. Configuration keys
     * use it in kebab-case ({@code acmeTickets} -> {@code kc-mcp.spi.acme-tickets.*}, see
     * {@link ProviderConfig#configId}). Defaults to the class name.
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
     * Hands the extension its own settings, {@code kc-mcp.spi.<id>.*} from the
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
     * @param config this extension's own settings, {@code kc-mcp.spi.<id>.*}
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
