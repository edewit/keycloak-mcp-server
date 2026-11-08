package com.github.thomasdarimont.keycloak.mcp.backend;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * The forward setup with a second, independent Keycloak as the system {@code other}: its
 * own keys, no demo realm, nobody logs in there. What the tests need is that it exists.
 */
public class TwoKeycloaksTestResource extends ForwardTestResource {

    static String otherBase;

    private GenericContainer<?> other;

    @Override
    @SuppressWarnings("resource")
    protected void bootstrapMore() {
        other = new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        other.start();
        otherBase = "http://" + other.getHost() + ":" + other.getMappedPort(8080);
    }

    @Override
    protected Map<String, String> extraConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("kc-mcp.systems.other.url", otherBase);
        // every system has a default realm, so the realm argument stays optional for the
        // tests
        config.put("kc-mcp.systems.other.default-realm", "master");
        // the default tenant verifies callers of the first Keycloak ("default"), the
        // default system is the second:
        // what the tenant verifies must not count as the second system's own issuer
        config.put("kc-mcp.default-system", "other");
        config.put("kc-mcp.startup-check", "warn");
        return config;
    }

    @Override
    public void stop() {
        super.stop();
        if (other != null) {
            other.stop();
        }
    }
}
