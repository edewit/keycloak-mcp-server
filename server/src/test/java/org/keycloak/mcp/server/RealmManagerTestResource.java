package org.keycloak.mcp.server;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Keycloak with a {@code demo} realm and a confidential client {@code mcp-mgr} whose
 * service account only holds {@code view-users} and {@code view-clients}. The server is
 * configured with the client_credentials grant against that client: the "realm-manager"
 * access level.
 */
public class RealmManagerTestResource implements QuarkusTestResourceLifecycleManager {

    private GenericContainer<?> keycloak;
    private final HttpClient http = HttpClient.newHttpClient();
    private String base;
    private String adminToken;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        keycloak = new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        base = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        try {
            bootstrap();
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Keycloak bootstrap failed", e);
        }
        return Map.of("kc-mcp.url", base, "kc-mcp.grant-type", "client_credentials", "kc-mcp.auth-realm", "demo",
                "kc-mcp.client-id", "mcp-mgr", "kc-mcp.client-secret", "mgr-secret", "kc-mcp.allowed-realms", "demo",
                "kc-mcp.default-realm", "demo", "kc-mcp.tool-exposure", "direct", "kc-mcp.startup-check", "fail");
    }

    private void bootstrap() throws IOException, InterruptedException {
        adminToken = new JsonObject(form("/realms/master/protocol/openid-connect/token",
                "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .getString("access_token");
        post("/admin/realms", new JsonObject().put("realm", "demo").put("enabled", true));
        post("/admin/realms/demo/users",
                new JsonObject().put("username", "bob").put("enabled", true).put("email", "bob@example.com"));
        String clientUuid = post("/admin/realms/demo/clients",
                new JsonObject().put("clientId", "mcp-mgr")
                    .put("secret", "mgr-secret")
                    .put("publicClient", false)
                    .put("serviceAccountsEnabled", true)
                    .put("standardFlowEnabled", false)
                    .put("directAccessGrantsEnabled", false));
        String saUser = new JsonObject(get("/admin/realms/demo/clients/" + clientUuid + "/service-account-user"))
            .getString("id");
        String rm = new JsonArray(get("/admin/realms/demo/clients?clientId=realm-management")).getJsonObject(0)
            .getString("id");
        JsonArray roles = new JsonArray();
        for (String role : new String[] { "view-users", "view-clients" }) {
            roles.add(new JsonObject(get("/admin/realms/demo/clients/" + rm + "/roles/" + role)));
        }
        post("/admin/realms/demo/users/" + saUser + "/role-mappings/clients/" + rm, roles);
    }

    private String form(String path, String body) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    private String get(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    /** POSTs JSON and returns the id from the Location header, if any. */
    private String post(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
    }

    private static void check(HttpResponse<String> r, String path) {
        if (r.statusCode() >= 300) {
            throw new IllegalStateException("Bootstrap " + path + " -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
