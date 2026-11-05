package com.github.thomasdarimont.keycloak.mcp.access;

/**
 * A role requirement, parsed from the strings given to {@code ToolSpec.roles(...)}:
 * <ul>
 * <li>{@code view-users} — shorthand for the {@code realm-management} client role,</li>
 * <li>{@code realm-management.view-users}, {@code my-app.auditor} — client role (split at
 * the last dot, so clientIds with dots work),</li>
 * <li>{@code realm:offline_access} — realm role.</li>
 * </ul>
 */
public record RoleRef(Kind kind, String client, String role) {

    public static final String REALM_MANAGEMENT = "realm-management";

    public enum Kind {
        REALM_MANAGEMENT, CLIENT, REALM
    }

    public static RoleRef parse(String ref) {
        String r = ref.trim();
        if (r.startsWith("realm:")) {
            return new RoleRef(Kind.REALM, null, r.substring("realm:".length()).trim());
        }
        int dot = r.lastIndexOf('.');
        if (dot > 0 && dot < r.length() - 1) {
            String client = r.substring(0, dot);
            String role = r.substring(dot + 1);
            return client.equals(REALM_MANAGEMENT) ? new RoleRef(Kind.REALM_MANAGEMENT, REALM_MANAGEMENT, role)
                    : new RoleRef(Kind.CLIENT, client, role);
        }
        return new RoleRef(Kind.REALM_MANAGEMENT, REALM_MANAGEMENT, r);
    }

    public boolean isRealmManagement() {
        return kind == Kind.REALM_MANAGEMENT;
    }

    @Override
    public String toString() {
        return switch (kind) {
            case REALM -> "realm:" + role;
            case REALM_MANAGEMENT -> role;
            case CLIENT -> client + "." + role;
        };
    }
}
