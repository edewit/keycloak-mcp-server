package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * Settings of the built-in policy provider ({@code kc-mcp.spi.policies.*}).
 *
 * @param groupScope {@code off}, {@code group} (caller must be in the target group or an
 * ancestor) or {@code organization} (caller and group share an organization)
 * @param managerRole role the caller must hold for group management under scope, e.g.
 * {@code realm:group-manager}
 * @param noEscalation callers may only grant / touch privileges within their own
 * effective roles
 * @param selfProtection what happens when a caller would delete or disable their own
 * account or drop their own administrative roles and group memberships: {@code reject},
 * {@code confirm} (only the human's own confirmation lets it through, by elicitation or a
 * confirmer that asks them such as CIBA; the model's flag does not count) or {@code off};
 * super roles do not bypass this one
 * @param selfProtectionTools tools the self-protection guards beyond the built-in ones,
 * or instead of them: tool name to the argument naming the user; an empty argument
 * removes a built-in tool from the guard
 * @param anonymous {@code allow} skips the checks for anonymous callers (unprotected
 * endpoint), {@code deny} refuses the guarded tools
 * @param superRoles callers holding one of these role keys bypass the group scope and
 * escalation checks
 */
public record PolicySettings(GroupScope groupScope, String managerRole, boolean noEscalation,
        SelfProtection selfProtection, Map<String, String> selfProtectionTools, boolean denyAnonymous,
        Set<String> superRoles) {

    public enum GroupScope {
        OFF, GROUP, ORGANIZATION
    }

    /**
     * How the self-protection answers; {@code true}/{@code false} in the configuration
     * mean reject/off.
     */
    public enum SelfProtection {
        OFF, REJECT, CONFIRM;

        static SelfProtection parse(String value) {
            String v = value.trim().toLowerCase(Locale.ROOT);
            return switch (v) {
                case "off", "false" -> OFF;
                case "reject", "true" -> REJECT;
                case "confirm" -> CONFIRM;
                default -> throw new IllegalArgumentException(
                        "kc-mcp.spi.policies.self-protection: 'reject', 'confirm' or 'off', not '" + value + "'");
            };
        }
    }

    public static final PolicySettings DISABLED = new PolicySettings(GroupScope.OFF, null, false, SelfProtection.OFF,
            Map.of(), false, Set.of());

    public PolicySettings {
        selfProtectionTools = selfProtectionTools == null ? Map.of() : Map.copyOf(selfProtectionTools);
        superRoles = superRoles == null ? Set.of() : Set.copyOf(superRoles);
    }

    public static PolicySettings from(ProviderConfig config) {
        GroupScope scope = GroupScope.valueOf(config.get("group-scope", "off").trim().toUpperCase(Locale.ROOT));
        String manager = config.get("manager-role").orElse(null);
        boolean noEscalation = config.getBoolean("no-escalation", true);
        SelfProtection selfProtection = SelfProtection.parse(config.get("self-protection", "reject"));
        Map<String, String> selfProtectionTools = new LinkedHashMap<>();
        config.get("self-protection-tools").ifPresent(v -> {
            for (String entry : v.split(",")) {
                if (entry.isBlank()) {
                    continue;
                }
                int eq = entry.indexOf('=');
                if (eq <= 0) {
                    throw new IllegalArgumentException("kc-mcp.spi.policies.self-protection-tools: entries are"
                            + " <tool>=<user argument> (an empty argument removes a built-in tool), not '"
                            + entry.trim() + "'");
                }
                selfProtectionTools.put(entry.substring(0, eq).trim(), entry.substring(eq + 1).trim());
            }
        });
        boolean denyAnonymous = "deny".equalsIgnoreCase(config.get("anonymous", "allow"));
        Set<String> supers = new LinkedHashSet<>(List.of("realm:admin", "realm-management.realm-admin"));
        config.get("super-roles").ifPresent(v -> {
            for (String s : v.split(",")) {
                if (!s.isBlank()) {
                    supers.add(s.trim());
                }
            }
        });
        return new PolicySettings(scope, manager, noEscalation, selfProtection, selfProtectionTools, denyAnonymous,
                supers);
    }

    public boolean enabled() {
        return groupScope != GroupScope.OFF || noEscalation || selfProtection != SelfProtection.OFF;
    }
}
