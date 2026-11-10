package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AuthorizationAccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a system registered through the admin API may put into its authorization blocks,
 * whatever the engine.
 */
class AdminSystemsAuthorizationTest {

    final DefaultKeycloakSystems systems = new DefaultKeycloakSystems(
            List.of(KeycloakSystem.builder("static", "https://sso.example.com").build()), "static", null,
            HostAllowList.of(List.of("*.example.com")));
    final AtomicReference<Boolean> validatedWithKey = new AtomicReference<>();
    final AtomicReference<String> refusal = new AtomicReference<>();

    final AuthorizationEngine authzen = new AuthorizationEngine() {
        @Override
        public String id() {
            return "authzen";
        }

        @Override
        public com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision decide(Request request) {
            return com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision.allow();
        }

        @Override
        public void validate(KeycloakSystem system, boolean systemKey) {
            validatedWithKey.set(systemKey);
            if (refusal.get() != null) {
                throw new IllegalArgumentException(refusal.get());
            }
        }
    };
    final AuthorizationAccessCheck engines = new AuthorizationAccessCheck(() -> List.of(authzen), n -> Optional.empty(),
            List::of);
    final com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain plan = new com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain(
            List.of(engines,
                    (com.github.thomasdarimont.keycloak.mcp.access.AccessCheck) new com.github.thomasdarimont.keycloak.mcp.access.AccessCheck() {
                        @Override
                        public String id() {
                            return "self-protection";
                        }

                        @Override
                        public Decision check(Context context) {
                            return Decision.allow();
                        }
                    }),
            id -> new com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig("access-check", id,
                    id.equals("self-protection") ? java.util.Map.of("locked", "true") : java.util.Map.of()));

    static KeycloakSystem dyn(String authorization) {
        return KeycloakSystem.builder("dyn", "https://dyn.example.com")
            .authorization(AuthorizationSettings.fromJson(new JsonObject(authorization)))
            .build();
    }

    String code(KeycloakSystem system) {
        return assertThrows(AdminException.class, () -> AdminSystems.checkAccess(system, systems, plan, engines, true))
            .code();
    }

    String code(String authorization) {
        return code(dyn(authorization));
    }

    @Test
    void urlsOfEveryEngineAreHeldToTheAllowList() {
        AdminSystems.checkAccess(
                dyn("{\"enabled\": true, \"authzen\": {\"url\": \"https://pdp.example.com/{system}/e\"}}"), systems,
                plan, engines, true);
        assertEquals(true, validatedWithKey.get());

        assertEquals("host_not_allowed", code("{\"authzen\": {\"url\": \"https://pdp.elsewhere.net/e\"}}"));
        assertEquals("host_not_allowed", code("{\"authzen\": {\"tokenUrl\": \"https://169.254.169.254/latest\"}}"));
        // a realm's block too
        assertEquals("host_not_allowed",
                code(dyn("{}").toBuilder()
                    .realm(new RealmSettings("acme",
                            AuthorizationSettings
                                .fromJson(new JsonObject("{\"authzen\": {\"url\": \"https://pdp.elsewhere.net\"}}"))))
                    .build()));
    }

    @Test
    void noFilesOfThisServerForAnyEngine() {
        assertEquals("local_file_setting", code("{\"authzen\": {\"jwtKeyFile\": \"/etc/kc-mcp/server.pem\"}}"));
        assertEquals("unknown_authorization_engine", code("{\"vendor\": {\"policy\": \"p\"}}"));
    }

    @Test
    void namedEnginesMustExist() {
        AdminException e = assertThrows(AdminException.class, () -> AdminSystems
            .checkAccess(dyn("{\"enabled\": true, \"acme-opa\": {}}"), systems, plan, engines, true));
        assertEquals("unknown_authorization_engine", e.code());
        assertTrue(e.getMessage().contains("acme-opa") && e.getMessage().contains("authzen"), e.getMessage());

        AuthorizationAccessCheck none = new AuthorizationAccessCheck(List::of, n -> Optional.empty(), List::of);
        assertEquals("unknown_authorization_engine",
                assertThrows(AdminException.class,
                        () -> AdminSystems.checkAccess(dyn("{\"enabled\": true}"), systems, plan, none, true))
                    .code(),
                "switched on, but nothing on this server could evaluate");
    }

    @Test
    void theEnginesOwnValidationDecidesTheRest() {
        refusal.set("kc-mcp.systems.dyn.authorization.authzen.auth=header needs header-value");
        AdminException e = assertThrows(AdminException.class, () -> AdminSystems
            .checkAccess(dyn("{\"authzen\": {\"auth\": \"header\"}}"), systems, plan, engines, false));

        assertEquals(400, e.status());
        assertEquals("invalid_authorization", e.code());
        assertTrue(e.getMessage().contains("header-value"));
        assertEquals(false, validatedWithKey.get());
    }

    static KeycloakSystem withAccess(String access) {
        return KeycloakSystem.builder("dyn", "https://dyn.example.com")
            .access(com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings.fromJson(new JsonObject(access),
                    "access."))
            .build();
    }

    @Test
    void entriesOnlyForChecksTheServerHasAndDidNotLock() {
        assertEquals("unknown_access_check", code(withAccess("{\"acme-ticket\": {\"order\": 5}}")));
        assertEquals("access_check_locked", code(withAccess("{\"self-protection\": {\"enabled\": false}}")));
        AdminSystems.checkAccess(withAccess("{\"acme-ticket\": {\"enabled\": false}}"), systems, plan, engines, true);
        AdminSystems.checkAccess(withAccess("{\"authorization\": {\"order\": 1}}"), systems, plan, engines, true);
    }

    @Test
    void settingsOfEveryCheckAreHeldToTheSameRules() {
        assertEquals("host_not_allowed",
                code(withAccess("{\"acme-ticket\": {\"enabled\": false, \"endpoint\": \"https://evil.test\"}}")));
    }
}
