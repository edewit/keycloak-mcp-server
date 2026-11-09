package com.github.thomasdarimont.keycloak.mcp.backend.config;

import org.eclipse.microprofile.config.ConfigProvider;

/**
 * The realm the default OIDC tenant verifies callers against; see
 * {@link DefaultTenantInterceptorFactory}.
 */
public final class DefaultTenant {

    private DefaultTenant() {
    }

    /**
     * {@code quarkus.oidc.auth-server-url}, configured or derived from the default
     * Keycloak system; {@code http://localhost:8080/realms/master} when there is no
     * system at all.
     */
    public static String authServerUrl() {
        return ConfigProvider.getConfig()
            .getOptionalValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL, String.class)
            .filter(v -> !v.isBlank())
            .orElse("http://localhost:8080/realms/master");
    }
}
