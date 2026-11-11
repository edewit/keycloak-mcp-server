package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class InstanceRoleInterceptorFactoryTest {

    static SmallRyeConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder()
            .withInterceptorFactories(new InstanceRoleInterceptorFactory(), new DevModeInterceptorFactory(),
                    new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
    }

    @Test
    void allChangesNothing() {
        SmallRyeConfig c = config(Map.of("kc-mcp.instance-role", "all"));
        assertNull(c.getRawValue("kc-mcp.mcp.enabled"));
        assertNull(c.getRawValue("kc-mcp.admin.enabled"));
        assertNull(c.getRawValue("kc-mcp.ui.enabled"));
        assertNull(config(Map.of()).getRawValue("kc-mcp.admin.enabled"), "no role is all");
    }

    @Test
    void mcpSwitchesTheAdminApiAndTheUiOff() {
        SmallRyeConfig c = config(Map.of("kc-mcp.instance-role", "mcp"));
        assertEquals("false", c.getRawValue("kc-mcp.admin.enabled"));
        assertEquals("false", c.getRawValue("kc-mcp.ui.enabled"));
        assertNull(c.getRawValue("kc-mcp.mcp.enabled"), "the mapping's default, on");
    }

    @Test
    void mcpDecidesOverTheUiStartDevAssumes(@TempDir Path home) {
        Map<String, String> dev = new HashMap<>(Map.of("kc-mcp.dev-mode", "true", "kcmcp.home.dir", home.toString(),
                "quarkus.datasource.db-kind", "h2"));
        assertEquals("true", config(dev).getRawValue("kc-mcp.ui.enabled"), "start-dev alone turns the UI on");
        dev.put("kc-mcp.instance-role", "mcp");
        assertEquals("false", config(dev).getRawValue("kc-mcp.ui.enabled"));
    }

    @Test
    void adminSwitchesTheMcpEndpointOffAndTheAdminApiOn() {
        SmallRyeConfig c = config(Map.of("kc-mcp.instance-role", "admin"));
        assertEquals("false", c.getRawValue("kc-mcp.mcp.enabled"));
        assertEquals("true", c.getRawValue("kc-mcp.admin.enabled"));
        assertNull(c.getRawValue("kc-mcp.ui.enabled"), "the UI stays a choice of its own");
    }

    @Test
    void anExplicitSwitchIsLeftForTheStartupCheckToRefuse() {
        SmallRyeConfig c = config(Map.of("kc-mcp.instance-role", "mcp", "kc-mcp.admin.enabled", "true"));
        assertEquals("true", c.getRawValue("kc-mcp.admin.enabled"));
        SmallRyeConfig a = config(Map.of("kc-mcp.instance-role", "admin", "kc-mcp.admin.enabled", "false"));
        assertEquals("false", a.getRawValue("kc-mcp.admin.enabled"), "an admin instance with the UI only");
    }

    @Test
    void theRoleIsCaseInsensitiveAndAnUnknownOneIsLeftToTheMapping() {
        assertEquals("false", config(Map.of("kc-mcp.instance-role", "MCP")).getRawValue("kc-mcp.admin.enabled"));
        assertNull(config(Map.of("kc-mcp.instance-role", "both")).getRawValue("kc-mcp.admin.enabled"));
    }
}
