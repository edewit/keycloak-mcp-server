package com.github.thomasdarimont.keycloak.mcp.server.spi;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ProviderConfigTest {

    @Test
    void idsBecomeKebabCase() {
        assertEquals("acme-ticket-checker", ProviderConfig.configId("acmeTicketChecker"));
        assertEquals("acme-ticket-checker", ProviderConfig.configId("AcmeTicketChecker"));
        assertEquals("acme-ticket-checker", ProviderConfig.configId("acme_ticket_checker"));
        assertEquals("acme-ticket-checker", ProviderConfig.configId("acme-ticket-checker"));
        assertEquals("acme-ticket-checker", ProviderConfig.configId(" acme ticket  checker "));
        assertEquals("com-acme-ticket-checker", ProviderConfig.configId("com.acme.TicketChecker"));
        assertEquals("ldap-sync-v2", ProviderConfig.configId("LDAPSyncV2"));
        assertEquals("users", ProviderConfig.configId("users"));
        assertEquals("outer-inner", ProviderConfig.configId("Outer$Inner"));
    }

    @Test
    void lookupUsesTheKebabCaseKeyAndFallsBackToTheRawId() {
        Map<String, Map<String, String>> spi = Map.of("acme-ticket-checker", Map.of("enabled", "false"), "rawId",
                Map.of("mode", "strict"));
        ProviderConfig c = ProviderConfig.forExtension("acmeTicketChecker", spi);
        assertFalse(c.getBoolean("enabled", true));
        assertEquals("kc-mcp.spi.acme-ticket-checker.", c.providerPrefix());
        assertEquals("KC_MCP_SPI_ACME_TICKET_CHECKER_", c.envPrefix());
        assertEquals("strict", ProviderConfig.forExtension("rawId", spi).get("mode", "none"));
        assertEquals("none", ProviderConfig.forExtension("unknown", spi).get("mode", "none"));
        assertEquals("none", ProviderConfig.forExtension("unknown", null).get("mode", "none"));
    }

    @Test
    void environmentVariablesAreResolvedWithTheIdKnown() {
        Map<String, Map<String, String>> spi = Map.of("auth-flows", Map.of("enabled", "true", "page-size", "20"));
        Map<String, String> env = Map.of("KC_MCP_SPI_AUTH_FLOWS_ENABLED", "false", "KC_MCP_SPI_AUTH_FLOWS_MAX_DEPTH",
                "3", "KC_MCP_SPI_AUTH_FLOWS_", "ignored", "KC_MCP_SPI_AUTH_FLOWSX_ENABLED", "other id",
                "KC_MCP_SPI_AUTH_ENABLED", "other id too");
        ProviderConfig c = ProviderConfig.forExtension("auth-flows", spi, env);
        assertFalse(c.getBoolean("enabled", true), "env overrides the properties entry");
        assertEquals("20", c.get("page-size", "none"), "properties entries without an env override stay");
        assertEquals(3, c.getInt("max-depth", 0));
        assertEquals(Map.of("enabled", "false", "page-size", "20", "max-depth", "3"), c.asMap());
        assertEquals("true", ProviderConfig.forExtension("auth-flows", spi, Map.of()).get("enabled", "none"));
    }
}
