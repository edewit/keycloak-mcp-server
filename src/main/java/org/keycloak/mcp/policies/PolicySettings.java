package org.keycloak.mcp.policies;

import java.util.Locale;

import org.keycloak.mcp.spi.ProviderConfig;

/**
 * Settings of the built-in policy provider ({@code kc-mcp.spi.policies.*}).
 *
 * @param groupScope      {@code off}, {@code group} (caller must be in the target group or an ancestor) or
 *                        {@code organization} (caller and group share an organization)
 * @param managerRole     role the caller must hold for group management under scope, e.g. {@code realm:group-manager}
 * @param noEscalation    callers may only grant / touch privileges within their own effective roles
 * @param anonymous       {@code allow} skips the checks for anonymous callers (unprotected endpoint), {@code deny}
 *                        refuses the guarded tools
 * @param superRoles      callers holding one of these role keys bypass both checks
 */
public record PolicySettings(GroupScope groupScope, String managerRole, boolean noEscalation, boolean denyAnonymous,
        java.util.Set<String> superRoles) {

    public enum GroupScope {
        OFF,
        GROUP,
        ORGANIZATION
    }

    public static final PolicySettings DISABLED = new PolicySettings(GroupScope.OFF, null, false, false,
            java.util.Set.of());

    public static PolicySettings from(ProviderConfig config) {
        GroupScope scope = GroupScope.valueOf(config.get("group-scope", "off").trim().toUpperCase(Locale.ROOT));
        String manager = config.get("manager-role").orElse(null);
        boolean noEscalation = config.getBoolean("no-escalation", true);
        boolean denyAnonymous = "deny".equalsIgnoreCase(config.get("anonymous", "allow"));
        java.util.Set<String> supers = new java.util.LinkedHashSet<>(java.util.List.of("realm:admin",
                "realm-management.realm-admin"));
        config.get("super-roles").ifPresent(v -> {
            for (String s : v.split(",")) {
                if (!s.isBlank()) {
                    supers.add(s.trim());
                }
            }
        });
        return new PolicySettings(scope, manager, noEscalation, denyAnonymous, supers);
    }

    public boolean enabled() {
        return groupScope != GroupScope.OFF || noEscalation;
    }
}
