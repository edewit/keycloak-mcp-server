package org.keycloak.mcp.guard;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * What the server's own access token can do. Derived from the token's
 * {@code realm_access} and {@code resource_access} claims:
 * <ul>
 * <li>{@code realm_access.roles} containing {@code admin} in the {@code master} realm =
 * super admin,</li>
 * <li>{@code resource_access.realm-management.roles} = realm-management roles in the
 * realm the client lives in,</li>
 * <li>{@code resource_access.<realm>-realm.roles} = realm-management roles in realm
 * {@code <realm>} granted to a master client,</li>
 * <li>any other {@code resource_access.<client>.roles} and {@code realm_access.roles} =
 * client / realm roles in the auth realm, for custom {@link RoleRef}s.</li>
 * </ul>
 * Implications mirror Keycloak's checks for realm-management roles: {@code manage-x}
 * satisfies {@code view-x}, {@code view-x} satisfies {@code query-x}, {@code realm-admin}
 * satisfies all. When a token carries no admin roles at all the roles are
 * {@link #UNKNOWN} and nothing is filtered.
 *
 * @param byRealm realm -> realm-management roles
 * @param clientRoles auth realm only: clientId -> roles (realm-management included)
 * @param realmRoles auth realm only: realm roles
 */
public record GrantedRoles(boolean known, boolean superAdmin, String authRealm, Map<String, Set<String>> byRealm,
        Map<String, Set<String>> clientRoles, Set<String> realmRoles) {

    public static final GrantedRoles UNKNOWN = new GrantedRoles(false, false, null, Map.of(), Map.of(), Set.of());

    private static final Map<String, List<String>> IMPLIED_BY = Map.of("query-users",
            List.of("view-users", "manage-users"), "query-groups", List.of("view-users", "manage-users"),
            "query-clients", List.of("view-clients", "manage-clients"), "query-realms",
            List.of("view-realm", "manage-realm"), "view-users", List.of("manage-users"), "view-clients",
            List.of("manage-clients"), "view-realm", List.of("manage-realm"), "view-identity-providers",
            List.of("manage-identity-providers"), "view-events", List.of("manage-events"), "view-authorization",
            List.of("manage-authorization"));

    public GrantedRoles {
        byRealm = copy(byRealm);
        clientRoles = copy(clientRoles);
        realmRoles = Set.copyOf(realmRoles == null ? Set.of() : realmRoles);
    }

    private static Map<String, Set<String>> copy(Map<String, Set<String>> m) {
        Map<String, Set<String>> c = new LinkedHashMap<>();
        if (m != null) {
            m.forEach((k, v) -> c.put(k, Set.copyOf(v)));
        }
        return Map.copyOf(c);
    }

    /**
     * Parses the payload of a JWT (no signature check: the token came from Keycloak over
     * our own connection).
     */
    public static GrantedRoles fromToken(String jwt, String authRealm) {
        if (jwt == null) {
            return UNKNOWN;
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return UNKNOWN;
        }
        try {
            JsonObject payload = new JsonObject(
                    new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            return fromClaims(payload, authRealm);
        }
        catch (RuntimeException e) {
            return UNKNOWN;
        }
    }

    public static GrantedRoles fromClaims(JsonObject payload, String authRealm) {
        Set<String> realmRoles = new LinkedHashSet<>();
        JsonObject realmAccess = payload.getJsonObject("realm_access");
        if (realmAccess != null) {
            realmAccess.getJsonArray("roles", new JsonArray()).forEach(r -> realmRoles.add(String.valueOf(r)));
        }
        boolean superAdmin = "master".equals(authRealm) && realmRoles.contains("admin");
        Map<String, Set<String>> byRealm = new LinkedHashMap<>();
        Map<String, Set<String>> clientRoles = new LinkedHashMap<>();
        JsonObject resourceAccess = payload.getJsonObject("resource_access", new JsonObject());
        for (String client : resourceAccess.fieldNames()) {
            JsonArray roles = resourceAccess.getJsonObject(client).getJsonArray("roles", new JsonArray());
            Set<String> set = new LinkedHashSet<>();
            roles.forEach(r -> set.add(String.valueOf(r)));
            clientRoles.put(client, set);
            if (client.equals(RoleRef.REALM_MANAGEMENT)) {
                byRealm.merge(authRealm, set, GrantedRoles::union);
            }
            else if (client.endsWith("-realm") && "master".equals(authRealm)) {
                byRealm.merge(client.substring(0, client.length() - "-realm".length()), set, GrantedRoles::union);
            }
        }
        boolean known = superAdmin || !byRealm.isEmpty();
        return new GrantedRoles(known, superAdmin, authRealm, byRealm, clientRoles, realmRoles);
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> s = new LinkedHashSet<>(a);
        s.addAll(b);
        return s;
    }

    /**
     * Realms the token has realm-management roles in (empty for super admins, who reach
     * every realm).
     */
    public Set<String> realms() {
        return byRealm.keySet();
    }

    public boolean reaches(String realm) {
        return !known || superAdmin || byRealm.containsKey(realm);
    }

    /**
     * Whether all {@code required} role refs are held in {@code realm}; unknown roles
     * never block.
     */
    public boolean permits(String realm, Set<String> required) {
        return missing(realm, required).isEmpty();
    }

    /**
     * Whether the refs are held in at least one realm; used for realm-agnostic listing
     * and search.
     */
    public boolean permitsAnyRealm(Set<String> required) {
        if (!known || superAdmin || required.isEmpty()) {
            return true;
        }
        Set<String> realms = new LinkedHashSet<>(byRealm.keySet());
        if (authRealm != null) {
            realms.add(authRealm);
        }
        for (String realm : realms) {
            if (missing(realm, required).isEmpty()) {
                return true;
            }
        }
        return false;
    }

    /**
     * The smallest set of required refs still missing in any realm the token reaches (for
     * search, where the target realm is not known yet); empty when some realm satisfies
     * them all.
     */
    public Set<String> missingAnyRealm(Set<String> required) {
        if (!known || superAdmin || required.isEmpty()) {
            return Set.of();
        }
        Set<String> realms = new LinkedHashSet<>(byRealm.keySet());
        if (authRealm != null) {
            realms.add(authRealm);
        }
        Set<String> best = null;
        for (String realm : realms) {
            Set<String> missing = missing(realm, required);
            if (best == null || missing.size() < best.size()) {
                best = missing;
            }
        }
        return best == null ? Set.copyOf(required) : best;
    }

    /**
     * Whether {@code role} (a realm-management role) is held or implied in {@code realm}.
     */
    public boolean holds(String realm, String role) {
        return !known || superAdmin || satisfiedManagement(byRealm.getOrDefault(realm, Set.of()), role);
    }

    /** Required refs not satisfied in {@code realm}, in declaration order. */
    public Set<String> missing(String realm, Set<String> required) {
        Set<String> missing = new LinkedHashSet<>();
        if (!known || superAdmin) {
            return missing;
        }
        for (String r : required) {
            if (!satisfied(realm, RoleRef.parse(r))) {
                missing.add(r);
            }
        }
        return missing;
    }

    boolean satisfied(String realm, RoleRef ref) {
        return switch (ref.kind()) {
            case REALM_MANAGEMENT -> satisfiedManagement(byRealm.getOrDefault(realm, Set.of()), ref.role());
            // custom client and realm roles only exist in the token of the auth realm
            case CLIENT ->
                realm.equals(authRealm) && clientRoles.getOrDefault(ref.client(), Set.of()).contains(ref.role());
            case REALM -> realm.equals(authRealm) && realmRoles.contains(ref.role());
        };
    }

    static boolean satisfiedManagement(Set<String> granted, String required) {
        if (granted.contains(required) || granted.contains("realm-admin")) {
            return true;
        }
        for (String stronger : IMPLIED_BY.getOrDefault(required, List.of())) {
            if (granted.contains(stronger)) {
                return true;
            }
        }
        return false;
    }
}
