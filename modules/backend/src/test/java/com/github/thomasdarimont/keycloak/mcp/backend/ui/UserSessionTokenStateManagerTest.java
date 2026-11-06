package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import io.quarkus.oidc.AuthorizationCodeTokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UserSessionTokenStateManagerTest {

    private final UserSessionTokenStateManager manager = new UserSessionTokenStateManager();

    private static String jwt(String payload) {
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return "eyJhbGciOiJub25lIn0." + b64 + ".sig";
    }

    @Test
    void readsClaimsWithoutVerifying() {
        String token = jwt("{\"sub\":\"u-1\",\"exp\":1700000000}");
        assertEquals("u-1", manager.claimOf(token, "sub"));
        assertEquals(1700000000L, manager.expOf(token));
        assertNull(manager.claimOf(token, "email"));
        assertNull(manager.claimOf("not a jwt", "sub"));
        assertEquals(0, manager.expOf(null));
        assertEquals(0, manager.expOf("a.b.c"));
    }

    @Test
    void rowLifetimeFollowsTheLatestTokenExpiry() {
        long now = 1_700_000_000_000L;
        AuthorizationCodeTokens tokens = new AuthorizationCodeTokens(jwt("{\"exp\":1700000300}"), "access",
                jwt("{\"exp\":1700001800}"));
        assertEquals(1700001800_000L + UserSessionTokenStateManager.SLACK.toMillis(), manager.expiresAt(tokens, now));
        // no readable expiry: the default lifetime
        assertEquals(now + UserSessionTokenStateManager.DEFAULT_LIFETIME.toMillis(),
                manager.expiresAt(new AuthorizationCodeTokens("opaque", "access", null), now));
        // a token that already expired still gets the slack, so a refresh in flight finds
        // the row
        assertEquals(now + UserSessionTokenStateManager.SLACK.toMillis(),
                manager.expiresAt(new AuthorizationCodeTokens(jwt("{\"exp\":1600000000}"), null, null), now));
    }
}
