package org.keycloak.mcp;

import java.time.Duration;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

/**
 * Starts a throw-away Keycloak (start-dev) and points the server at it with password auth.
 * Image overridable with {@code -Dkeycloak.image=...}.
 */
public class KeycloakTestResource implements QuarkusTestResourceLifecycleManager {

    static final String IMAGE = System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.8.1");

    private GenericContainer<?> keycloak;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        keycloak = new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withExposedPorts(8080)
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                .withCommand("start-dev")
                .waitingFor(Wait.forHttp("/realms/master").forPort(8080).withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        String url = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        return Map.of(
                "kc-mcp.url", url,
                "kc-mcp.grant-type", "password",
                "kc-mcp.auth-realm", "master",
                "kc-mcp.username", "admin",
                "kc-mcp.password", "admin",
                "kc-mcp.tool-exposure", "direct");
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
