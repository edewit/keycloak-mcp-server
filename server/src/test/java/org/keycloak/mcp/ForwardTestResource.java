package org.keycloak.mcp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Keycloak with a {@code demo} realm shaped like the example: public client
 * {@code mcp-consumer} whose tokens carry {@code aud=mcp-admin}, {@code alice} with
 * {@code realm-admin}, {@code carol} with {@code view-users} only, and a second client
 * {@code other-app} without the audience. The server runs in delegation mode
 * {@code forward} with the OIDC tenant on and no credentials of its own.
 */
public class ForwardTestResource implements QuarkusTestResourceLifecycleManager {

    static String base;

    private GenericContainer<?> keycloak;
    private final HttpClient http = HttpClient.newHttpClient();
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
        return Map.ofEntries(Map.entry("kc-mcp.url", base), Map.entry("kc-mcp.auth-realm", "demo"),
                Map.entry("kc-mcp.delegation", "forward"), Map.entry("kc-mcp.default-realm", "demo"),
                Map.entry("kc-mcp.allowed-realms", "demo"), Map.entry("kc-mcp.tool-exposure", "direct"),
                Map.entry("kc-mcp.grant-type", "client_credentials"), Map.entry("kc-mcp.username", ""),
                Map.entry("kc-mcp.password", ""), Map.entry("quarkus.oidc.tenant-enabled", "true"),
                Map.entry("quarkus.oidc.auth-server-url", base + "/realms/demo"),
                Map.entry("quarkus.oidc.token.audience", "mcp-admin"));
    }

    private void bootstrap() throws IOException, InterruptedException {
        adminToken = new JsonObject(form("/realms/master/protocol/openid-connect/token",
                "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .getString("access_token");
        post("/admin/realms", new JsonObject().put("realm", "demo").put("enabled", true));
        String scopeId = post("/admin/realms/demo/client-scopes",
                new JsonObject().put("name", "keycloak-mcp")
                    .put("protocol", "openid-connect")
                    .put("attributes", new JsonObject().put("include.in.token.scope", "false"))
                    .put("protocolMappers",
                            new JsonArray().add(new JsonObject().put("name", "mcp audience")
                                .put("protocol", "openid-connect")
                                .put("protocolMapper", "oidc-audience-mapper")
                                .put("config", new JsonObject().put("included.custom.audience", "mcp-admin")
                                    .put("access.token.claim", "true")))));
        String consumer = publicClient("mcp-consumer");
        put("/admin/realms/demo/clients/" + consumer + "/default-client-scopes/" + scopeId);
        publicClient("other-app");

        String rm = new JsonArray(get("/admin/realms/demo/clients?clientId=realm-management")).getJsonObject(0)
            .getString("id");
        user("alice", rm, "realm-admin");
        user("carol", rm, "view-users");
        user("bob", rm);
    }

    private String publicClient(String clientId) throws IOException, InterruptedException {
        return post("/admin/realms/demo/clients",
                new JsonObject().put("clientId", clientId)
                    .put("publicClient", true)
                    .put("standardFlowEnabled", true)
                    .put("directAccessGrantsEnabled", true)
                    .put("fullScopeAllowed", true)
                    .put("redirectUris", new JsonArray().add("http://127.0.0.1:*/*")));
    }

    private void user(String name, String realmManagementClientId, String... roles)
            throws IOException, InterruptedException {
        // emailVerified + names: otherwise the realm's user profile demands required
        // actions ("not fully set up")
        String id = post("/admin/realms/demo/users",
                new JsonObject().put("username", name)
                    .put("enabled", true)
                    .put("email", name + "@example.com")
                    .put("emailVerified", true)
                    .put("firstName", name)
                    .put("lastName", "Test")
                    .put("credentials", new JsonArray()
                        .add(new JsonObject().put("type", "password").put("value", name).put("temporary", false))));
        JsonArray mappings = new JsonArray();
        for (String role : roles) {
            mappings
                .add(new JsonObject(get("/admin/realms/demo/clients/" + realmManagementClientId + "/roles/" + role)));
        }
        if (!mappings.isEmpty()) {
            post("/admin/realms/demo/users/" + id + "/role-mappings/clients/" + realmManagementClientId, mappings);
        }
    }

    /** Password grant for a user of the demo realm with the given public client. */
    public static String token(String client, String user, String password) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(base + "/realms/demo/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "grant_type=password&client_id=" + client + "&username=" + user + "&password=" + password))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check(r, "token for " + user);
            return new JsonObject(r.body()).getString("access_token");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
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

    private void put(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .PUT(HttpRequest.BodyPublishers.noBody())
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
    }

    private String post(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
    }

    private static void check(HttpResponse<String> r, String what) {
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(what + " -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
