package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The forward setup with a second, independent Keycloak as the system {@code other}: its
 * own keys, no demo realm; its {@code admin} logs in at the master realm through a public
 * client {@code mcp-consumer} shaped like the first Keycloak's (audience
 * {@code mcp-admin}, the {@code kc-admin-api} scope).
 */
public class TwoKeycloaksTestResource extends ForwardTestResource {

    static String otherBase;

    private GenericContainer<?> other;

    @Override
    @SuppressWarnings("resource")
    protected void bootstrapMore() throws IOException, InterruptedException {
        other = new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        other.start();
        otherBase = "http://" + other.getHost() + ":" + other.getMappedPort(8080);
        String admin = otherToken("admin-cli", "admin", "admin");
        HttpResponse<String> r = HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder(URI.create(otherBase + "/admin/realms/master/clients"))
                .header("Authorization", "Bearer " + admin)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(new JsonObject().put("clientId", "mcp-consumer")
                    .put("publicClient", true)
                    .put("standardFlowEnabled", true)
                    .put("directAccessGrantsEnabled", true)
                    .put("fullScopeAllowed", true)
                    .put("defaultClientScopes",
                            new JsonArray().add("roles").add("profile").add("basic").add("email").add("kc-admin-api"))
                    .put("redirectUris", new JsonArray().add("http://127.0.0.1:*/*"))
                    .put("protocolMappers",
                            new JsonArray().add(new JsonObject().put("name", "mcp audience")
                                .put("protocol", "openid-connect")
                                .put("protocolMapper", "oidc-audience-mapper")
                                .put("config",
                                        new JsonObject().put("included.custom.audience", "mcp-admin")
                                            .put("access.token.claim", "true"))))
                    .encode()))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(
                    "mcp-consumer at the other Keycloak -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    /** Password grant at the other Keycloak's master realm. */
    public static String otherToken(String client, String user, String password) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(otherBase + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "grant_type=password&client_id=" + client + "&username=" + user + "&password=" + password))
                    .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 300) {
                throw new IllegalStateException(
                        "token for " + user + " at the other Keycloak -> HTTP " + r.statusCode() + " " + r.body());
            }
            return new JsonObject(r.body()).getString("access_token");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
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
