package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiTenantTest {

    @Test
    void providerAliasFromQuarkusCookies() {
        assertEquals("corp", UiTenant.aliasOfCookie("q_session_kc-mcp-ui-corp"));
        assertEquals("corp", UiTenant.aliasOfCookie("q_session_kc-mcp-ui-corp_chunk_1"));
        assertEquals("corp", UiTenant.aliasOfCookie("q_auth_kc-mcp-ui-corp_abc123"));
        assertEquals("default", UiTenant.aliasOfCookie("q_auth_kc-mcp-ui-default"));
        assertNull(UiTenant.aliasOfCookie("q_session"));
        assertNull(UiTenant.aliasOfCookie("JSESSIONID"));
        assertEquals("corp", UiTenant.aliasOf("kc-mcp-ui-corp"));
        assertEquals("default", UiTenant.aliasOf(null));
    }

    @Test
    void bffPaths() {
        assertTrue(UiTenant.isBffPath("/bff"));
        assertTrue(UiTenant.isBffPath("/bff/login"));
        assertFalse(UiTenant.isBffPath("/bffx"));
        assertTrue(UiTenant.isApiPath("/bff/api/systems"));
        assertFalse(UiTenant.isApiPath("/bff/me"));
    }

    @Test
    void spaRoutesGetTheIndexPage() {
        assertTrue(UiRoutes.isIndexRoute("/ui/"));
        assertTrue(UiRoutes.isIndexRoute("/ui/systems"));
        assertTrue(UiRoutes.isIndexRoute("/ui/systems/acme"));
        assertFalse(UiRoutes.isIndexRoute("/ui/index.html"));
        assertFalse(UiRoutes.isIndexRoute("/ui/assets/index-abc.js"));
        // a dot marks a file: routes of the app must not end in a dotted segment
        assertFalse(UiRoutes.isIndexRoute("/ui/systems/v1.2"));
    }
}
