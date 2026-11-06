package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AuditLogAccess;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.DefaultConfirmer;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.TrafficLoggingProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.Profile;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveTest {

    private static final JsonObject SCHEMA = InputSchema.builder()
        .string("username", "who")
        .string("pin", "a one-time PIN")
        .sensitive()
        .stringMap("config", "provider config")
        .sensitiveKeys("clientSecret")
        .string("keycloakRealm", "a realm")
        .build();

    @Test
    void declaredArgumentsAndMapKeysAreMarkedForClients() {
        JsonObject pin = SCHEMA.getJsonObject("properties").getJsonObject("pin");
        assertEquals(true, pin.getBoolean("writeOnly"));
        assertEquals("password", pin.getString("format"));
        JsonObject secret = SCHEMA.getJsonObject("properties")
            .getJsonObject("config")
            .getJsonObject("properties")
            .getJsonObject("clientSecret");
        assertEquals(true, secret.getBoolean("writeOnly"));
        assertTrue(SCHEMA.getJsonObject("properties").getJsonObject("config").containsKey("additionalProperties"),
                "other keys stay free");
    }

    @Test
    void redactionCoversDeclaredValuesMapKeysAndNameHints() {
        Map<String, Object> out = Sensitive.redact(SCHEMA,
                Map.of("username", "dave", "pin", "1234", "config",
                        Map.of("clientId", "app", "clientSecret", "s3cr3t", "bindCredential", "pw"), "password",
                        "undeclared", "keycloakRealm", "demo"));
        assertEquals("dave", out.get("username"));
        assertEquals(Sensitive.MASK, out.get("pin"), "declared, though the name looks harmless");
        Map<?, ?> config = (Map<?, ?>) out.get("config");
        assertEquals("app", config.get("clientId"));
        assertEquals(Sensitive.MASK, config.get("clientSecret"), "declared map key");
        assertEquals(Sensitive.MASK, config.get("bindCredential"), "name hint inside a map");
        assertEquals(Sensitive.MASK, out.get("password"), "name hint for an undeclared argument");
        assertEquals("demo", out.get("keycloakRealm"), "the hints look at how a name ends");
        for (String setting : List.of("passwordPolicy", "resetPasswordAllowed", "accessTokenLifespan",
                "webAuthnPasswordlessPolicy")) {
            assertFalse(Sensitive.byName(setting), setting + " is a setting, not a secret");
        }
        for (String secret : List.of("password", "clientSecret", "client_secret", "bindCredential", "refreshToken",
                "privateKey", "keyTab", "apiKey")) {
            assertTrue(Sensitive.byName(secret), secret);
        }
    }

    @Test
    void theIdpAndSmtpSecretsNoLongerReachTheAuditLog() {
        List<AuditEvent> events = new ArrayList<>();
        AuditListener capture = events::add;
        ToolSpec idp = ToolSpec.builder("keycloak_idp_create")
            .title("Create identity provider")
            .description("d")
            .category(Category.IDP)
            .write()
            .schema(InputSchema.builder()
                .string("alias", "a")
                .stringMap("config", "c")
                .sensitiveKeys("clientSecret", "privateKey"))
            .handler(call -> ToolResult.ok(Map.of()))
            .build();
        AuditLogAccess.record(List.of(capture), idp,
                Map.of("alias", "google", "config", Map.of("clientId", "app", "clientSecret", "very-secret")));
        Map<?, ?> config = (Map<?, ?>) events.get(0).args().get("config");
        assertEquals(Sensitive.MASK, config.get("clientSecret"));
        assertEquals("app", config.get("clientId"));
        assertFalse(events.get(0).sensitiveResult());

        ToolSpec getSecret = ToolSpec.builder("keycloak_client_get_secret")
            .title("Get client secret")
            .description("d")
            .category(Category.CLIENTS)
            .read()
            .sensitiveResult()
            .handler(call -> ToolResult.ok(Map.of()))
            .build();
        AuditLogAccess.record(List.of(capture), getSecret, Map.of("clientId", "app"));
        assertTrue(events.get(1).sensitiveResult(), "the audit says a secret was handed out");
    }

    @Test
    void theElicitationPromptNeverShowsAPassword() {
        ToolSpec reset = ToolSpec.builder("keycloak_user_reset_password")
            .title("Reset password")
            .description("d")
            .category(Category.USERS)
            .destructive()
            .schema(InputSchema.builder().string("id", "user").string("password", "new").sensitive())
            .handler(call -> ToolResult.ok(Map.of()))
            .build();
        List<String> shown = new ArrayList<>();
        Prompter prompter = new Prompter() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public Optional<Boolean> askYesNo(String message) {
                shown.add(message);
                return Optional.of(false);
            }
        };
        new DefaultConfirmer().confirm(new ConfirmationRequest(reset, null, "demo",
                Map.of("id", "u1", "password", "Hunter2!"), false, Caller.NONE, prompter));
        assertTrue(shown.get(0).contains("u1"), shown.get(0));
        assertFalse(shown.get(0).contains("Hunter2"), shown.get(0));
    }

    @Test
    void trafficLoggingStopsASharedServerAndWarnsALocalOne() {
        TrafficLoggingProfileCheck check = new TrafficLoggingProfileCheck();
        ProfileCheckContext sharedOn = new ProfileCheckContext(Profile.SHARED, true, null, null,
                name -> Optional.of("true"));
        assertEquals(1, check.problems(sharedOn).size());
        ProfileCheckContext localOn = new ProfileCheckContext(Profile.LOCAL, false, null, null,
                name -> Optional.of("true"));
        assertTrue(check.problems(localOn).isEmpty());
        assertEquals(1, check.warnings(localOn).size());
        ProfileCheckContext sharedOff = new ProfileCheckContext(Profile.SHARED, true, null, null,
                name -> Optional.of("false"));
        assertTrue(check.problems(sharedOff).isEmpty());
    }

    static AuditEvent event() {
        return new AuditEvent(Instant.now(), "t", null, null, null, Map.of(), "ok", null, "direct", Caller.NONE, "-",
                "-", Duration.ZERO);
    }
}
