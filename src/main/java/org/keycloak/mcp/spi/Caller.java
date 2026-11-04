package org.keycloak.mcp.spi;

import java.util.Set;

/**
 * Who is acting through the MCP connection. Anonymous ({@link #NONE}) while the endpoint
 * is unauthenticated; filled from the caller's token once the endpoint is protected
 * (OIDC); {@link #delegated()} becomes true when the admin call itself is made with the
 * caller's permissions (token exchange).
 *
 * @param subject stable id (token {@code sub}), or {@code null}
 * @param name username / display name, or {@code null}
 * @param realm Keycloak realm that issued the caller's token (last segment of
 * {@code iss}), or {@code null}
 * @param delegated the admin call is made on behalf of this caller with their permissions
 * @param roles caller roles as found in the token: {@code realm:<role>} and
 * {@code <clientId>.<role>}
 */
public record Caller(String subject, String name, String realm, boolean delegated, Set<String> roles) {

    public static final Caller NONE = new Caller(null, null, null, false, Set.of());

    public Caller {
        roles = Set.copyOf(roles == null ? Set.of() : roles);
    }

    public boolean isAnonymous() {
        return subject == null;
    }

    public boolean hasRole(String roleRef) {
        return roles.contains(roleRef);
    }

    public static Caller of(String subject, String name, String realm, Set<String> roles) {
        return new Caller(subject, name, realm, false, roles);
    }

    public static Caller delegated(String subject, String name, String realm, Set<String> roles) {
        return new Caller(subject, name, realm, true, roles);
    }

    public Caller asDelegated() {
        return new Caller(subject, name, realm, true, roles);
    }
}
