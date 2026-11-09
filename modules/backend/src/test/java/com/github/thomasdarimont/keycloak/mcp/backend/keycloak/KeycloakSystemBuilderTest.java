package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The builder, the withers and the JSON parser agree on what a system is. */
class KeycloakSystemBuilderTest {

    @Test
    void buildsWithDefaultsAndPlainValues() {
        KeycloakSystem s = KeycloakSystem.builder("acme", " https://sso.acme.example ")
            .clientId("keycloak-mcp-server")
            .defaultRealm("acme-dev")
            .allowedRealm("acme-dev")
            .allowedRealm(" acme-prod ")
            .allowedRealm("")
            .displayName("ACME Corp.")
            .description("  ACME's Keycloak  ")
            .version(null)
            .build();
        assertEquals("acme", s.name());
        assertEquals("https://sso.acme.example", s.url(), "trimmed");
        assertEquals(GrantType.CLIENT_CREDENTIALS, s.grantType());
        assertEquals(ClientAuth.PRIVATE_KEY_JWT, s.clientAuth());
        assertEquals("master", s.authRealm());
        assertEquals(Optional.of("keycloak-mcp-server"), s.clientId());
        assertEquals(Optional.empty(), s.clientSecret());
        assertEquals(Set.of("acme-dev", "acme-prod"), s.allowedRealms(), "blank realms dropped, others trimmed");
        assertEquals(Optional.of("ACME's Keycloak"), s.description());
        assertEquals(Optional.empty(), s.version());

        // the same system through the long constructor
        KeycloakSystem viaConstructor = new KeycloakSystem("acme", "https://sso.acme.example",
                GrantType.CLIENT_CREDENTIALS, ClientAuth.PRIVATE_KEY_JWT, "master", Optional.of("keycloak-mcp-server"),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.of("acme-dev"),
                Set.of("acme-dev", "acme-prod"), Optional.empty(), Optional.empty(), Optional.of("ACME Corp."),
                Optional.of("ACME's Keycloak"));
        assertEquals(viaConstructor, s);

        // withers and toBuilder keep everything else
        assertEquals(s.withDescription(null).description(), Optional.empty());
        assertEquals(s, s.withDescription("ACME's Keycloak"));
        assertEquals(s.toBuilder().build(), s);
        assertEquals(Optional.of("vault:acme/secret"),
                s.toBuilder()
                    .clientAuth(ClientAuth.CLIENT_SECRET)
                    .clientSecret("vault:acme/secret")
                    .build()
                    .clientSecret());
        assertEquals(Set.of(), s.toBuilder().allowedRealms(List.of()).build().allowedRealms(), "replaced, not added");

        assertThrows(IllegalArgumentException.class, () -> KeycloakSystem.builder("", "https://x").build());
        assertThrows(IllegalArgumentException.class, () -> KeycloakSystem.builder("x", " ").build());
        // a trusted issuer that is no absolute http(s) URL would never match: refused up
        // front
        for (String bad : List.of("sso.example/realms/demo", "https://", "ldap://sso.example",
                "https://sso.example?x=1", "https://sso.example/realms/demo#frag",
                "https://admin:secret@sso.example/realms/demo")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> KeycloakSystem.builder("x", "https://x").trustedIssuer(bad).build(), bad);
            assertTrue(e.getMessage().contains(bad), e.getMessage());
        }
        KeycloakSystem ok = KeycloakSystem.builder("x", "https://x")
            .trustedIssuer("https://sso.example/realms/demo")
            .trustedIssuer("http://host1:8080/auth")
            .build();
        assertEquals(2, ok.trustedIssuers().size());
    }

    @Test
    void theJsonShapeOfTheSystemsFileAndTheAdminApiParsesToTheSame() {
        JsonObject json = new JsonObject().put("url", "https://sso.acme.example")
            .put("clientId", "keycloak-mcp-server")
            .put("defaultRealm", "acme-dev")
            .put("allowedRealms", new JsonArray().add("acme-dev").add("acme-prod"))
            .put("displayName", "ACME Corp.")
            .put("description", "ACME's Keycloak");
        KeycloakSystem parsed = FileSystemKeycloakSystemRepository.parseSystem(json, "acme");
        KeycloakSystem built = KeycloakSystem.builder("acme", "https://sso.acme.example")
            .clientId("keycloak-mcp-server")
            .defaultRealm("acme-dev")
            .allowedRealms(List.of("acme-dev", "acme-prod"))
            .displayName("ACME Corp.")
            .description("ACME's Keycloak")
            .build();
        assertEquals(built, parsed);
        assertTrue(FileSystemKeycloakSystemRepository.parseSystem(new JsonObject().put("url", "https://x"), "bare")
            .description()
            .isEmpty());
    }
}
