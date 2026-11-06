package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessTokenSource;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Systems that repositories add at runtime are seen by the role and capability discovery:
 * before the first one exists nothing is filtered, afterwards its roles count.
 */
class DynamicSystemsRoleDiscoveryTest {

    static String token(String... roles) {
        String payload = "{\"resource_access\":{\"realm-management\":{\"roles\":[\"" + String.join("\",\"", roles)
                + "\"]}}}";
        return "h." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".s";
    }

    static AccessTokenSource source(String... roles) {
        return new AccessTokenSource() {
            @Override
            public String accessToken() {
                return token(roles);
            }

            @Override
            public String authRealm() {
                return "master";
            }
        };
    }

    @Test
    void systemsRegisteredLaterAreCovered() {
        List<String> systems = new ArrayList<>();
        RoleDiscovery roles = new RoleDiscovery(() -> List.copyOf(systems), name -> source("view-users"), true);
        CapabilityDiscovery caps = new CapabilityDiscovery(() -> List.copyOf(systems),
                name -> new ServerCapabilities("26.8.2", Set.of("organization"), true));

        // no system yet (dynamic systems before the first registration): nothing to
        // filter on
        assertTrue(roles.systems().isEmpty());
        assertTrue(roles.anySystemPeek(g -> g.permitsAnyRealm(Set.of("manage-users"))), "unknown roles permit");
        assertTrue(roles.anySystem(g -> g.permitsAnyRealm(Set.of("manage-users"))));
        assertFalse(roles.get().known());
        assertFalse(caps.get().featuresKnown());

        // a repository adds one: its token decides from now on
        systems.add("acme");
        assertEquals(List.of("acme"), roles.systems());
        assertTrue(roles.anySystem(g -> g.permitsAnyRealm(Set.of("view-users"))));
        assertFalse(roles.anySystem(g -> g.permitsAnyRealm(Set.of("manage-users"))), "known roles filter");
        assertTrue(roles.anySystemPeek(g -> g.permitsAnyRealm(Set.of("view-users"))), "cached after get");
        assertTrue(caps.get().hasFeature("organization"));
        assertEquals(List.of("acme"), caps.systems());

        // gone again: back to unknown
        systems.clear();
        assertTrue(roles.anySystemPeek(g -> g.permitsAnyRealm(Set.of("manage-users"))));
    }
}
