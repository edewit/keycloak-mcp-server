package org.keycloak.mcp.spi;

import java.util.List;

import org.keycloak.mcp.catalog.ToolSpec;

/**
 * Extension point, modelled on Keycloak's {@code ProviderFactory}: one provider contributes a set of tools.
 * <p>
 * Providers are discovered in two ways:
 * <ul>
 * <li>{@link java.util.ServiceLoader}: list the implementation class in
 * {@code META-INF/services/org.keycloak.mcp.spi.ToolProvider} of any jar on the classpath. Jars dropped into the
 * {@code providers/} directory next to the packaged application are picked up at startup, like Keycloak's own
 * {@code providers/} folder.</li>
 * <li>CDI: any bean implementing this interface.</li>
 * </ul>
 * Per-provider configuration lives under {@code kc-mcp.spi.<id>.*} (env {@code KC_MCP_SPI_<ID>_*}); the key
 * {@code enabled=false} switches a provider off.
 */
public interface ToolProvider {

    /** Unique, stable id such as {@code users} or {@code acme-custom}. */
    String id();

    /** Human readable name, e.g. "User management". Defaults to the id. */
    default String displayName() {
        return id();
    }

    /** One or two sentences on what the provider's tools cover. */
    default String description() {
        return "";
    }

    /** Providers are initialised in ascending order; ties broken by id. */
    default int order() {
        return 0;
    }

    /** Called once at startup before {@link #tools(ToolProviderContext)}. */
    default void init(ToolProviderContext context) {
    }

    /** The tools this provider contributes. Names must be globally unique. */
    List<ToolSpec> tools(ToolProviderContext context);

    /** Called on shutdown. */
    default void close() {
    }
}
