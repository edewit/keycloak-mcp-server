package org.keycloak.mcp.spi;

import java.util.Map;
import java.util.Set;

/**
 * Who is acting through the MCP connection. Anonymous ({@link #NONE}) while the endpoint
 * is unauthenticated; filled from the caller's token once the endpoint is protected
 * (OIDC); {@link #delegated()} becomes true when the admin call itself is made with the
 * caller's permissions.
 * <p>
 * The token travels along for access checks that need more than roles ({@link #claims()},
 * {@link #claim(String)}, {@link #rawToken()}); {@link #toString()} never prints it and
 * audit events carry a {@link #withoutToken()} copy.
 *
 * @param subject stable id (token {@code sub}), or {@code null}
 * @param name username / display name, or {@code null}
 * @param realm Keycloak realm that issued the caller's token (last segment of
 * {@code iss}), or {@code null}
 * @param delegated the admin call is made on behalf of this caller with their permissions
 * @param roles caller roles as found in the token: {@code realm:<role>} and
 * {@code <clientId>.<role>}
 * @param rawToken the bearer token as presented, or {@code null}
 * @param claims the token's payload as plain Java values (maps, lists, strings, numbers,
 * booleans); empty when there is no token
 */
public record Caller(String subject, String name, String realm, boolean delegated, Set<String> roles, String rawToken,
        Map<String, Object> claims) {

    public static final Caller NONE = new Caller(null, null, null, false, Set.of(), null, Map.of());

    public Caller {
        roles = Set.copyOf(roles == null ? Set.of() : roles);
        claims = claims == null ? Map.of()
                : java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(claims));
    }

    public Caller(String subject, String name, String realm, boolean delegated, Set<String> roles) {
        this(subject, name, realm, delegated, roles, null, Map.of());
    }

    public boolean isAnonymous() {
        return subject == null;
    }

    public boolean hasRole(String roleRef) {
        return roles.contains(roleRef);
    }

    /** One claim of the token, or {@code null}. */
    public Object claim(String name) {
        return claims.get(name);
    }

    public boolean hasToken() {
        return rawToken != null;
    }

    public static Caller of(String subject, String name, String realm, Set<String> roles) {
        return new Caller(subject, name, realm, false, roles);
    }

    public static Caller delegated(String subject, String name, String realm, Set<String> roles) {
        return new Caller(subject, name, realm, true, roles);
    }

    public Caller asDelegated() {
        return new Caller(subject, name, realm, true, roles, rawToken, claims);
    }

    /** The same caller carrying their token and its parsed claims. */
    public Caller withToken(String raw, Map<String, Object> parsedClaims) {
        return new Caller(subject, name, realm, delegated, roles, raw, parsedClaims);
    }

    /**
     * The same caller without the credential (claims stay), for logs and audit events.
     */
    public Caller withoutToken() {
        return rawToken == null ? this : new Caller(subject, name, realm, delegated, roles, null, claims);
    }

    /** Never prints the token. */
    @Override
    public String toString() {
        return "Caller[subject=" + subject + ", name=" + name + ", realm=" + realm + ", delegated=" + delegated
                + ", roles=" + roles + ", token=" + (rawToken == null ? "none" : "present") + "]";
    }

}
