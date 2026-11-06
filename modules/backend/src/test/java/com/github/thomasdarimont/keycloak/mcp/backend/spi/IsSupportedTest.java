package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Extensions that cannot work with the current configuration are left out. */
class IsSupportedTest {

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    /**
     * Supported only when its own setting {@code needs} is set; {@code boom} makes the
     * check throw.
     */
    static final class Picky implements AuditListener {
        private final String id;

        Picky(String id) {
            this.id = id;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
            if (config.getBoolean("boom", false)) {
                throw new IllegalStateException("cannot tell");
            }
            return config.get("needs").isPresent();
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    }

    @Test
    void enabledSwitchFirstThenIsSupported() {
        Picky p = new Picky("picky");
        assertFalse(Extensions.usable(p, "AuditListener", config(Map.of())), "the setting is missing");
        assertTrue(Extensions.usable(p, "AuditListener", config(Map.of("kc-mcp.spi.picky.needs", "x"))));
        assertFalse(
                Extensions.usable(p, "AuditListener",
                        config(Map.of("kc-mcp.spi.picky.needs", "x", "kc-mcp.spi.picky.enabled", "false"))),
                "switched off wins");
        assertFalse(Extensions.usable(p, "AuditListener", config(Map.of("kc-mcp.spi.picky.boom", "true"))),
                "a failing check leaves it out");
    }

    @Test
    void theDefaultSupportsEverything() {
        AuditListener plain = event -> {
        };
        assertTrue(Extensions.usable(plain, "AuditListener", config(Map.of())));
    }

    @Test
    void theRegistryLeavesUnsupportedExtensionsOut() {
        Extensions discovery = new Extensions(null, getClass().getClassLoader(), null) {
            @Override
            @SuppressWarnings("unchecked")
            public <T> List<T> discover(Class<T> spi) {
                return spi == AuditListener.class ? (List<T>) List.of(new Picky("with"), new Picky("without"))
                        : List.of();
            }
        };
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry(discovery, null,
                config(Map.of("kc-mcp.spi.with.needs", "yes")));
        assertEquals(List.of("with"), registry.extensions(AuditListener.class).stream().map(l -> l.id()).toList());
    }
}
