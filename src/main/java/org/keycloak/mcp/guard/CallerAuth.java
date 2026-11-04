package org.keycloak.mcp.guard;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.keycloak.mcp.config.DelegationMode;
import org.keycloak.mcp.config.McpServerConfig;

import io.quarkus.runtime.StartupEvent;

/**
 * How callers of the MCP endpoint are authenticated: whether the OIDC tenant verifies
 * bearer tokens, whether an authenticated caller is required (401 challenge otherwise)
 * and whose credentials reach Keycloak.
 */
@ApplicationScoped
public class CallerAuth {

    private final DelegationMode delegation;
    private final boolean required;
    private final boolean oidcEnabled;

    @Inject
    public CallerAuth(McpServerConfig config) {
        this(config.delegation(), config.requireCaller(),
                ConfigProvider.getConfig().getOptionalValue("quarkus.oidc.tenant-enabled", Boolean.class).orElse(true));
    }

    public CallerAuth(DelegationMode delegation, boolean requireCaller, boolean oidcEnabled) {
        this.delegation = delegation;
        this.required = requireCaller || delegation == DelegationMode.FORWARD;
        this.oidcEnabled = oidcEnabled;
    }

    void validate(@Observes StartupEvent event) {
        if (required && !oidcEnabled) {
            throw new IllegalStateException("kc-mcp.delegation=" + delegation.name().toLowerCase()
                    + " / kc-mcp.require-caller=true need the MCP endpoint to authenticate callers: set "
                    + "quarkus.oidc.tenant-enabled=true (env QUARKUS_OIDC_TENANT_ENABLED) and point "
                    + "quarkus.oidc.auth-server-url at the realm that issues the caller tokens");
        }
    }

    public DelegationMode delegation() {
        return delegation;
    }

    public boolean forward() {
        return delegation == DelegationMode.FORWARD;
    }

    /** Unauthenticated MCP requests are refused with a 401 challenge. */
    public boolean required() {
        return required;
    }

    public boolean oidcEnabled() {
        return oidcEnabled;
    }
}
