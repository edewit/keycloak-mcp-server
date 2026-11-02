package org.keycloak.mcp.spi;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;

/**
 * Resolves the {@link Caller} for the current tool invocation. The default implementation reads the Quarkus
 * {@code SecurityIdentity} of the MCP request (populated when the endpoint is protected with OIDC).
 */
public interface CallerProvider {

    Caller current(FeatureArguments args);
}
