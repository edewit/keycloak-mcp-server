package org.keycloak.mcp.spi;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;

/**
 * Resolves the {@link Caller} for the current tool invocation. The default implementation
 * reads the Quarkus {@code SecurityIdentity} of the MCP request (populated when the
 * endpoint is protected with OIDC).
 */
public interface CallerProvider {

    Caller current(FeatureArguments args);

    /**
     * The caller's raw access token, forwarded to Keycloak in delegation mode
     * {@code forward}; {@code null} when the caller is anonymous or the provider has no
     * token.
     */
    default String accessToken(FeatureArguments args) {
        return null;
    }
}
