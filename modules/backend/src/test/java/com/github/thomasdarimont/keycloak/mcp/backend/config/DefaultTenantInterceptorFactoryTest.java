package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DefaultTenantInterceptorFactoryTest {

    static String authServerUrl(Map<String, String> properties) {
        SmallRyeConfig c = new SmallRyeConfigBuilder().withInterceptorFactories(new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
        return c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL);
    }

    @Test
    void theOnlySystemIsTheDefaultTenant() {
        assertEquals("http://a/realms/master", authServerUrl(Map.of("kc-mcp.systems.acme.url", "http://a/")));
        assertEquals("http://a/realms/corp", authServerUrl(
                Map.of("kc-mcp.systems.acme.url", "http://a", "kc-mcp.system-defaults.auth-realm", "corp")));
    }

    @Test
    void theNamedDefaultSystemWinsOverTheOneCalledDefault() {
        Map<String, String> two = Map.of("kc-mcp.systems.default.url", "http://d", "kc-mcp.systems.prod.url",
                "http://p", "kc-mcp.systems.prod.auth-realm", "ops");
        assertEquals("http://d/realms/master", authServerUrl(two));
        Map<String, String> named = new java.util.HashMap<>(two);
        named.put("kc-mcp.default-system", "prod");
        assertEquals("http://p/realms/ops", authServerUrl(named));
    }

    @Test
    void severalSystemsWithoutADefaultDeriveNothing() {
        assertNull(authServerUrl(Map.of("kc-mcp.systems.a.url", "http://a", "kc-mcp.systems.b.url", "http://b")));
    }

    @Test
    void repositoryOnlyDeploymentsDeriveNothingFromIgnoredBlocks() {
        assertNull(authServerUrl(Map.of("kc-mcp.systems.default.url", "http://d", "kc-mcp.static-systems", "false")));
    }

    @Test
    void aConfiguredValueIsLeftAlone() {
        assertEquals("http://explicit/realms/x", authServerUrl(Map.of("kc-mcp.systems.default.url", "http://d",
                "quarkus.oidc.auth-server-url", "http://explicit/realms/x")));
    }
}
