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
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        String url = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        return Map.ofEntries(Map.entry("kc-mcp.url", url), Map.entry("kc-mcp.grant-type", "password"),
                Map.entry("kc-mcp.auth-realm", "master"), Map.entry("kc-mcp.username", "admin"),
                Map.entry("kc-mcp.password", "admin"), Map.entry("kc-mcp.tool-exposure", "direct"),
                Map.entry("kc-mcp.systems.primary.url", url), Map.entry("kc-mcp.systems.mirror.url", url),
                Map.entry("kc-mcp.systems.mirror.allowed-realms", "master"),
                Map.entry("kc-mcp.default-system", "primary"), Map.entry("kc-mcp.spi.policies.group-scope", "group"),
                Map.entry("kc-mcp.spi.policies.manager-role", "realm:create-realm"),
                Map.entry("kc-mcp.spi.policies.no-escalation", "true"));
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
