package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Optional;
import java.util.Set;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.DatabaseKeyVault;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.DatabaseKeycloakSystemRepository;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A configured datasource switches the storage module on: systems come from the database
 * next to the static one, the key vault creates keys, the audit log writes rows.
 */
@QuarkusTest
@TestProfile(StorageProfile.class)
class StorageTest {

    @Inject
    StorageConfig storage;

    @Inject
    KeycloakSystems systems;

    @Inject
    SigningKeys keys;

    @Inject
    AuditLogAccess audit;

    @Test
    void aDatasourceTurnsTheDatabaseStorageOn() {
        assertTrue(storage.enabled(), "derived from quarkus.datasource.jdbc.url");
        assertEquals(DatabaseKeyVault.ID, keys.vault().id(), "the database vault replaces the file vault");
        DatabaseKeycloakSystemRepository repo = ((DefaultKeycloakSystems) systems).repository()
            .repository(DatabaseKeycloakSystemRepository.class)
            .orElseThrow();

        repo.save(new KeycloakSystem("tenant-db", "http://127.0.0.1:1", GrantType.CLIENT_CREDENTIALS,
                ClientAuth.PRIVATE_KEY_JWT, "master", Optional.of("keycloak-mcp-server"), Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.of("tenant"), Set.of(), Optional.empty())
            .withDisplayName("Tenant DB"));
        assertTrue(systems.names().contains("tenant-db"), systems.names().toString());

        McpClient mcp = new McpClient().initialize(false);
        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject().put("system", "tenant-db")));
        assertEquals("tenant-db", who.getString("system"), who.encode());

        // the vault creates the system's key on first use and publishes it
        String body = given().get("/auth/keys/tenant-db/jwks.json").then().statusCode(200).extract().asString();
        JsonObject key = new JsonObject(body).getJsonArray("keys").getJsonObject(0);
        assertEquals("RSA", key.getString("kty"));
        assertEquals(body, given().get("/auth/keys/tenant-db/jwks.json").then().statusCode(200).extract().asString(),
                "stored, not regenerated");
        given().get("/auth/keys/nope/jwks.json").then().statusCode(404);

        // a real tool call (meta tools such as whoami are not audited) leaves an audit
        // row
        JsonObject search = McpClient.text(mcp.callTool("keycloak_user_search",
                new JsonObject().put("system", "tenant-db").put("realm", "tenant").put("search", "bob")));
        assertEquals("keycloak_unreachable", search.getString("error"), search.encode());
        assertTrue(
                audit.listener()
                    .recent(10)
                    .stream()
                    .anyMatch(e -> "keycloak_user_search".equals(e.tool) && "tenant-db".equals(e.system)
                            && "keycloak_unreachable".equals(e.outcome) && e.args.contains("\"search\":\"bob\"")),
                "user search on tenant-db audited in the database");

        repo.delete("tenant-db");
        assertTrue(systems.find("tenant-db").isEmpty(), "gone from the database, gone from the server");
    }

    /**
     * Reaches the database audit listener the way the server does: through the registry.
     */
    @jakarta.enterprise.context.ApplicationScoped
    public static class AuditLogAccess {
        @Inject
        com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry registry;

        DatabaseAuditListener listener() {
            return registry.extensions(com.github.thomasdarimont.keycloak.mcp.audit.AuditListener.class)
                .stream()
                .filter(DatabaseAuditListener.class::isInstance)
                .map(DatabaseAuditListener.class::cast)
                .findFirst()
                .orElseThrow();
        }
    }
}
