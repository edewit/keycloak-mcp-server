package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
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

    @Test
    void requiredExtensionsFailClosed() {
        Picky p = new Picky("picky");
        IllegalStateException off = Assertions.assertThrows(IllegalStateException.class,
                () -> Extensions.usable(p, "AccessCheck", config(Map.of("kc-mcp.spi.picky.required", "true",
                        "kc-mcp.spi.picky.enabled", "false", "kc-mcp.spi.picky.needs", "x"))));
        assertTrue(off.getMessage().contains("switched off"), off.getMessage());
        IllegalStateException unsupported = Assertions.assertThrows(IllegalStateException.class,
                () -> Extensions.usable(p, "AccessCheck", config(Map.of("kc-mcp.spi.picky.required", "true"))));
        assertTrue(unsupported.getMessage().contains("not supported"), unsupported.getMessage());
        assertTrue(Extensions.usable(p, "AccessCheck",
                config(Map.of("kc-mcp.spi.picky.required", "true", "kc-mcp.spi.picky.needs", "x"))));
    }

    @Test
    void aFailingIsSupportedStopsASharedServer() {
        Picky p = new Picky("picky");
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, () -> Extensions.usable(p,
                "Confirmer", config(Map.of("kc-mcp.spi.picky.boom", "true", "kc-mcp.profile", "shared"))));
        assertTrue(e.getMessage().contains("profile shared"), e.getMessage());
        assertFalse(Extensions.usable(p, "Confirmer", config(Map.of("kc-mcp.spi.picky.boom", "true"))),
                "local: logged and left out");
    }

    @Test
    void aRequiredExtensionThatIsNotInstalledStopsTheStart() {
        assertEquals(List.of("acme-policy"),
                Extensions.missingRequired(
                        config(Map.of("kc-mcp.spi.acme-policy.required", "true", "kc-mcp.spi.other.required", "false")),
                        Set.of()));
        assertTrue(Extensions
            .missingRequired(config(Map.of("kc-mcp.spi.acme-policy.required", "true")), Set.of("acme-policy"))
            .isEmpty(), "installed");

        Extensions empty = new Extensions(null, getClass().getClassLoader(), null) {
            @Override
            public <T> List<T> discover(Class<T> spi) {
                return List.of();
            }
        };
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry(empty, null,
                config(Map.of("kc-mcp.spi.acme-policy.required", "true")));
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, () -> registry.onStart(null));
        assertTrue(e.getMessage().contains("acme-policy"), e.getMessage());
    }
}
