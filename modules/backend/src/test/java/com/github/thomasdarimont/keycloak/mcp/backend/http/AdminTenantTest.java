package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminAccessFilter;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminAccessFilterTest;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.oidc.OidcTenantConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An admin request is never verified by the default tenant, which is the MCP callers'.
 */
class AdminTenantTest {

    static EntryTenantResolver resolver(String token, String issuer) {
        McpServerConfig.Admin admin = AdminAccessFilterTest.admin(token, issuer);
        EntryTenantResolver r = new EntryTenantResolver();
        r.config = (McpServerConfig) Proxy.newProxyInstance(McpServerConfig.class.getClassLoader(),
                new Class<?>[] { McpServerConfig.class }, (p, m, a) -> {
                    if (m.getName().equals("admin")) {
                        return admin;
                    }
                    throw new UnsupportedOperationException(m.getName());
                });
        return r;
    }

    @Test
    void withoutAnIssuerEveryAdminRequestGetsADisabledTenant() {
        OidcTenantConfig t = resolver("secret", null).adminTenant("Bearer eyJ-an-mcp-token");
        assertFalse(t.tenantEnabled());
    }

    @Test
    void withAnIssuerTokensGoToTheAdminTenantAndTheStaticTokenToNone() {
        EntryTenantResolver r = resolver("secret", "https://sso.example.com/realms/ops");
        OidcTenantConfig t = r.adminTenant("Bearer eyJ-a-token");
        assertTrue(t.tenantEnabled());
        assertEquals(AdminAccessFilter.ADMIN_TENANT, t.tenantId().orElseThrow());
        assertFalse(r.adminTenant("Bearer secret").tenantEnabled());
    }
}
