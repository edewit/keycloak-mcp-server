package com.github.thomasdarimont.keycloak.mcp.backend;

import java.time.Duration;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

/**
 * Starts a throw-away Keycloak (start-dev) and points the server at it with password
 * auth. Image overridable with {@code -Dkeycloak.image=...}.
 */
public class KeycloakTestResource implements QuarkusTestResourceLifecycleManager {

    static final String IMAGE = System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.8.2");

    private GenericContainer<?> keycloak;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        keycloak = new GenericContainer<>(DockerImageName.parse(IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withEnv("KC_FEATURES", "identity-brokering-api:v2")
            .withEnv("KC_FEATURES_DISABLED", "twitter-broker")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        String url = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        return Map.ofEntries(Map.entry("kc-mcp.system-defaults.grant-type", "password"),
                Map.entry("kc-mcp.system-defaults.auth-realm", "master"),
                Map.entry("kc-mcp.system-defaults.username", "admin"),
                Map.entry("kc-mcp.system-defaults.password", "admin"), Map.entry("kc-mcp.tool-exposure", "direct"),
                // the baseline's "default" system is switched off: this test has primary
                // and mirror
                Map.entry("kc-mcp.systems.default.url", ""), Map.entry("kc-mcp.systems.primary.url", url),
                Map.entry("kc-mcp.systems.mirror.url", url),
                Map.entry("kc-mcp.systems.mirror.allowed-realms", "master"),
                Map.entry("kc-mcp.default-system", "primary"),
                Map.entry("kc-mcp.spi.access-check.group-scope.default", "on"),
                Map.entry("kc-mcp.spi.access-check.group-scope.scope", "group"),
                Map.entry("kc-mcp.spi.access-check.group-scope.manager-role", "realm:create-realm"),
                Map.entry("kc-mcp.spi.access-check.no-escalation.default", "on"));
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
