package org.keycloak.mcp.guard;

/**
 * Hands out the server's current admin access token, so the guard package can inspect its
 * roles without depending on the admin client.
 */
public interface AccessTokenSource {

    /**
     * The current (cached, refreshed as needed) access token, or {@code null} if none can
     * be obtained.
     */
    String accessToken();

    /** Realm the token was issued by. */
    String authRealm();
}
