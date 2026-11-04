package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.util.Map;
import java.util.Set;
import jakarta.json.Json;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.spi.Caller;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityIdentityCallerProviderTest {

    static JsonWebToken jwt(Map<String, Object> claims) {
        return new JsonWebToken() {
            @Override
            public String getName() {
                return (String) claims.get("upn");
            }

            @Override
            public Set<String> getClaimNames() {
                return claims.keySet();
            }

            @SuppressWarnings("unchecked")
            @Override
            public <T> T getClaim(String claimName) {
                return (T) claims.get(claimName);
            }
        };
    }

    @Test
    void anonymousIdentity() {
        SecurityIdentity anon = QuarkusSecurityIdentity.builder()
            .setAnonymous(true)
            .setPrincipal(new QuarkusPrincipal(""))
            .build();
        assertTrue(SecurityIdentityCallerProvider.fromIdentity(anon).isAnonymous());
        assertTrue(SecurityIdentityCallerProvider.fromIdentity(null).isAnonymous());
    }

    @Test
    void jwtIdentityCarriesSubjectRealmAndRoles() {
        JsonWebToken token = jwt(Map.of("sub", "1234-5678", "upn", "alice@example.com", "preferred_username", "alice",
                "raw_token", "eyJhbGciOiJub25lIn0.e30.sig", "iss", "https://sso.example.com/auth/realms/demo",
                "realm_access",
                Json.createObjectBuilder().add("roles", Json.createArrayBuilder().add("group-manager")).build(),
                "resource_access",
                Json.createObjectBuilder()
                    .add("my-app", Json.createObjectBuilder().add("roles", Json.createArrayBuilder().add("auditor")))
                    .build()));
        SecurityIdentity identity = QuarkusSecurityIdentity.builder()
            .setPrincipal(token)
            .addRole("group-manager")
            .build();
        Caller c = SecurityIdentityCallerProvider.fromIdentity(identity);
        assertEquals("1234-5678", c.subject());
        assertEquals("alice", c.name());
        assertEquals("demo", c.realm());
        assertFalse(c.delegated());
        assertTrue(c.hasRole("realm:group-manager"));
        assertTrue(c.hasRole("my-app.auditor"));
        // the token and its claims travel along for access checks, as plain Java values
        assertEquals("eyJhbGciOiJub25lIn0.e30.sig", c.rawToken());
        assertEquals("alice", c.claim("preferred_username"));
        assertEquals(java.util.List.of("group-manager"), ((Map<?, ?>) c.claim("realm_access")).get("roles"));
        assertFalse(c.claims().containsKey("raw_token"));
        assertFalse(c.toString().contains("eyJ"), c.toString());
        assertTrue(c.toString().contains("token=present"), c.toString());
        assertFalse(c.withoutToken().hasToken());
        assertEquals("alice", c.withoutToken().claim("preferred_username"));
        assertTrue(c.asDelegated().hasToken());
    }

    @Test
    void plainPrincipalFallsBackToName() {
        SecurityIdentity identity = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("bob"))
            .addRole("viewer")
            .build();
        Caller c = SecurityIdentityCallerProvider.fromIdentity(identity);
        assertEquals("bob", c.subject());
        assertEquals("bob", c.name());
        assertTrue(c.hasRole("realm:viewer"));
        assertEquals("demo", SecurityIdentityCallerProvider.realmOf("http://h/realms/demo/"));
    }
}
