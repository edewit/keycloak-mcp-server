package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Presets and access blocks at startup, and what the {@code validate} command reports
 * beyond: the systems of the repositories, which do not stop a start.
 */
class AccessValidationTest {

    static McpServerConfig config(Map<String, String> values) {
        Map<String, String> v = new HashMap<>(values);
        v.putIfAbsent("kc-mcp.systems.default.url", "https://sso.example");
        v.putIfAbsent("kc-mcp.systems.default.client-secret", "s");
        SmallRyeConfig c = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(v, "test", 500))
            .build();
        return c.getConfigMapping(McpServerConfig.class);
    }

    @AfterEach
    void endValidation() {
        System.clearProperty(ValidationRun.PROPERTY);
    }

    @Test
    void aCycleInTheServersPresetsStopsTheStart() {
        McpServerConfig c = config(Map.of("kc-mcp.presets.a.extends", "b", "kc-mcp.presets.b.extends", "a"));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new AccessPolicy(false, List.of()).runStartupChecks(c));

        assertTrue(e.getMessage().contains("a -> b -> a"), e.getMessage());
    }

    @Test
    void aConfiguredSystemReferencingAnUnknownPresetStopsTheStart() {
        McpServerConfig c = config(Map.of("kc-mcp.systems.default.realms.lab.preset", "nope"));

        assertThrows(IllegalStateException.class, () -> new AccessPolicy(false, List.of()).runStartupChecks(c));
    }

    @Test
    void validateReportsTheStoredSystemsToo() {
        McpServerConfig c = config(Map.of());
        InMemoryKeycloakSystemRepository stored = new InMemoryKeycloakSystemRepository("db",
                List.of(KeycloakSystem.builder("tenant", "https://sso.tenant")
                    .presets(List.of(Preset.fromJson("x", new JsonObject("{\"extends\": \"y\"}"), "presets.x."),
                            Preset.fromJson("y", new JsonObject("{\"extends\": \"x\"}"), "presets.y.")))
                    .build()));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(
                List.of(KeycloakSystem.builder("default", "https://sso.example").build()), "default", null,
                HostAllowList.ANY, List.of(stored));
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(), null,
                null, Explanations.AUTO, systems, DelegationMode.OFF);

        policy.runStartupChecks(c); // a stored system does not stop a start
        System.setProperty(ValidationRun.PROPERTY, "true");
        ValidationRun.guard(() -> policy.runStartupChecks(c));

        assertTrue(ValidationRun.problems().stream().anyMatch(p -> p.contains("tenant") && p.contains("x -> y -> x")),
                ValidationRun.problems().toString());
    }
}
