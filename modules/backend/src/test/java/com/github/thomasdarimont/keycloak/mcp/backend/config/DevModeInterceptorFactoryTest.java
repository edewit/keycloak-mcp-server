package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.Map;
import java.util.Set;
import java.util.stream.StreamSupport;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DevModeInterceptorFactoryTest {

    static SmallRyeConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder()
            .withInterceptorFactories(new DevModeInterceptorFactory(), new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
    }

    static Set<String> names(SmallRyeConfig c) {
        return StreamSupport.stream(c.getPropertyNames().spliterator(), false)
            .collect(java.util.stream.Collectors.toSet());
    }

    @Test
    void devModeWithoutASystemAssumesTheLocalKeycloak() {
        SmallRyeConfig c = config(Map.of("kc-mcp.dev-mode", "true"));
        assertEquals("http://localhost:8080", c.getRawValue("kc-mcp.systems.default.url"));
        assertTrue(names(c).contains("kc-mcp.systems.default.url"), "the systems mapping finds it by name");
        assertEquals("http://localhost:8080/realms/master",
                c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL),
                "the default tenant follows the assumed system");
    }

    @Test
    void aConfiguredSystemOfAnyNameSwitchesTheAssumptionOff() {
        SmallRyeConfig c = config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.systems.acme.url", "http://a"));
        assertNull(c.getRawValue("kc-mcp.systems.default.url"));
        assertFalse(names(c).contains("kc-mcp.systems.default.url"));
        assertEquals("http://a/realms/master", c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL));
        assertEquals("http://d", config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.systems.default.url", "http://d"))
            .getRawValue("kc-mcp.systems.default.url"), "a configured default stays");
    }

    @Test
    void outsideDevModeOrWithRepositoriesOnlyNothingIsAssumed() {
        assertNull(config(Map.of()).getRawValue("kc-mcp.systems.default.url"));
        assertNull(config(Map.of("kc-mcp.dev-mode", "false")).getRawValue("kc-mcp.systems.default.url"));
        assertNull(config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.static-systems", "false"))
            .getRawValue("kc-mcp.systems.default.url"));
    }
}
