package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.ArrayList;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExtensionLifecycleTest {

    private final List<String> calls = new ArrayList<>();

    private final Extensions extensions = new Extensions(null, getClass().getClassLoader(), null);

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private final class Recording implements AuditListener {
        private final String id;

        private final boolean failsToClose;

        Recording(String id, boolean failsToClose) {
            this.id = id;
            this.failsToClose = failsToClose;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public void configure(ProviderConfig config) {
            calls.add("configure " + id);
        }

        @Override
        public void close() {
            calls.add("close " + id);
            if (failsToClose) {
                throw new IllegalStateException("cannot close");
            }
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    }

    @Test
    void anExtensionPointIsDiscoveredOnce() {
        List<AuditListener> first = extensions.discover(AuditListener.class);
        assertFalse(first.isEmpty(), "the test class path registers listeners");
        assertSame(first.getFirst(), extensions.discover(AuditListener.class).getFirst());
    }

    @Test
    void anExtensionIsDecidedOnce() {
        Recording e = new Recording("a", false);
        assertTrue(extensions.admit(e, "AuditListener", config(Map.of())));
        assertTrue(extensions.admit(e, "AuditListener", config(Map.of())));
        assertEquals(List.of("configure a"), calls);
    }

    @Test
    void closesLastAdmittedFirstAndOnceDespiteFailures() {
        extensions.admit(new Recording("a", false), "AuditListener", config(Map.of()));
        extensions.admit(new Recording("b", true), "AuditListener", config(Map.of()));
        calls.clear();
        extensions.closeExtensions();
        extensions.closeExtensions();
        assertEquals(List.of("close b", "close a"), calls);
    }

    @Test
    void anExtensionThatDidNotTakePartIsNotClosed() {
        assertFalse(extensions.admit(new Recording("off", false), "AuditListener",
                config(Map.of("kc-mcp.spi.audit-listener.off.enabled", "false"))));
        extensions.closeExtensions();
        assertEquals(List.of(), calls);
    }
}
