package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        Map<String, Map<String, Map<String, String>>> spi = Map.of("access-check",
                Map.of("acme-ticket-checker", Map.of("enabled", "false"), "rawId", Map.of("mode", "strict")));
        ProviderConfig c = ProviderConfig.forExtension("access-check", "acmeTicketChecker", spi, Map.of());
        assertFalse(c.getBoolean("enabled", true));
        assertEquals("kc-mcp.spi.access-check.acme-ticket-checker.", c.providerPrefix());
        assertEquals("KC_MCP_SPI_ACCESS_CHECK_ACME_TICKET_CHECKER_", c.envPrefix());
        assertEquals("strict", ProviderConfig.forExtension("access-check", "rawId", spi, Map.of()).get("mode", "none"));
        assertEquals("none", ProviderConfig.forExtension("access-check", "unknown", spi, Map.of()).get("mode", "none"));
        assertEquals("none",
                ProviderConfig.forExtension("access-check", "unknown", null, Map.of()).get("mode", "none"));
    }

    @Test
    void environmentVariablesAreResolvedWithTheIdKnown() {
        Map<String, Map<String, Map<String, String>>> spi = Map.of("tools",
                Map.of("auth-flows", Map.of("enabled", "true", "page-size", "20")));
        Map<String, String> env = Map.of("KC_MCP_SPI_TOOLS_AUTH_FLOWS_ENABLED", "false",
                "KC_MCP_SPI_TOOLS_AUTH_FLOWS_MAX_DEPTH", "3", "KC_MCP_SPI_TOOLS_AUTH_FLOWS_", "ignored",
                "KC_MCP_SPI_TOOLS_AUTH_FLOWSX_ENABLED", "other id", "KC_MCP_SPI_TOOLS_AUTH_ENABLED", "other id too");
        ProviderConfig c = ProviderConfig.forExtension("tools", "auth-flows", spi, env);
        assertFalse(c.getBoolean("enabled", true), "env overrides the properties entry");
        assertEquals("20", c.get("page-size", "none"), "properties entries without an env override stay");
        assertEquals(3, c.getInt("max-depth", 0));
        assertEquals(Map.of("enabled", "false", "page-size", "20", "max-depth", "3"), c.asMap());
        assertEquals("true", ProviderConfig.forExtension("tools", "auth-flows", spi, Map.of()).get("enabled", "none"));
    }

    @Test
    void theCommandLineBeatsTheEnvironment() {
        String property = "kc-mcp.spi.tools.precedence-check.enabled";
        Map<String, String> env = Map.of("KC_MCP_SPI_TOOLS_PRECEDENCE_CHECK_ENABLED", "false");
        System.setProperty(property, "true");
        try {
            assertTrue(ProviderConfig.forExtension("tools", "precedence-check", Map.of(), env)
                .getBoolean("enabled", false));
            assertTrue(
                    ProviderConfig.forExtension("tools", "precedenceCheck", Map.of(), env).getBoolean("enabled", false),
                    "the id is matched in kebab-case");
        }
        finally {
            System.clearProperty(property);
        }
        assertFalse(
                ProviderConfig.forExtension("tools", "precedence-check", Map.of(), env).getBoolean("enabled", true));
    }

    @Test
    void theSameIdUnderTwoExtensionPointsHasSeparateSettings() {
        Map<String, Map<String, Map<String, String>>> spi = Map.of("tools", Map.of("acme", Map.of("enabled", "false")),
                "prompts", Map.of("acme", Map.of("language", "de")));
        assertFalse(ProviderConfig.forExtension("tools", "acme", spi, Map.of()).getBoolean("enabled", true));
        assertTrue(ProviderConfig.forExtension("prompts", "acme", spi, Map.of()).getBoolean("enabled", true));
        assertEquals("de", ProviderConfig.forExtension("prompts", "acme", spi, Map.of()).get("language", "en"));
        assertEquals(Map.of(),
                ProviderConfig.forExtension("tools", "acme", spi, Map.of("KC_MCP_SPI_PROMPTS_ACME_LANGUAGE", "fr"))
                    .asMap()
                    .entrySet()
                    .stream()
                    .filter(e -> e.getKey().equals("language"))
                    .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
    }
}
