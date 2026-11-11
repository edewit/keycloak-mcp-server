package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * Settings of one of the built-in policy checks, from its effective settings
 * ({@link #forCheck}: {@code kc-mcp.spi.access-check.<id>.*} with the system's and the
 * realm's {@code access.<id>} entry over it).
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
        OFF, REJECT, CONFIRM
    }

    public static final ConfigProperty ANONYMOUS = ConfigProperty.choice("anonymous", "allow", "deny")
        .withDefault("allow");

    public static final ConfigProperty SUPER_ROLES = ConfigProperty.list("super-roles");

    public static final ConfigProperty SCOPE = ConfigProperty.choice("scope", GroupScope.class).withDefault("group");

    public static final ConfigProperty MANAGER_ROLE = ConfigProperty.string("manager-role");

    public static final ConfigProperty MODE = ConfigProperty.choice("mode", SelfProtection.class)
        .withAliases("true", "reject", "false", "off")
        .withDefault("reject");

    public static final ConfigProperty TOOLS = ConfigProperty.list("tools");

    /** The settings the built-in check of this id reads. */
    public static ConfigSpec spec(String checkId) {
        return switch (checkId) {
            case GroupScopeCheck.ID -> ConfigSpec.of(ANONYMOUS, SUPER_ROLES, SCOPE, MANAGER_ROLE)
                .withHints(ConfigHint.when(MANAGER_ROLE.name()).is(SCOPE.name(), "group", "organization"));
            case NoEscalationCheck.ID -> ConfigSpec.of(ANONYMOUS, SUPER_ROLES);
            case SelfProtectionCheck.ID -> ConfigSpec.of(ANONYMOUS, SUPER_ROLES, MODE, TOOLS)
                .withHints(ConfigHint.when(TOOLS.name()).is(MODE.name(), "reject", "confirm"));
            default -> ConfigSpec.EMPTY;
        };
    }

    public static final PolicySettings DISABLED = new PolicySettings(GroupScope.OFF, null, false, SelfProtection.OFF,
            Map.of(), false, Set.of());

    public PolicySettings {
        selfProtectionTools = selfProtectionTools == null ? Map.of() : Map.copyOf(selfProtectionTools);
        superRoles = superRoles == null ? Set.of() : Set.copyOf(superRoles);
    }

    /** The settings a check of the given id reads from its effective settings. */
    public static PolicySettings forCheck(String checkId, ProviderConfig config) {
        boolean denyAnonymous = "deny".equals(config.readChoice(ANONYMOUS));
        Set<String> supers = new LinkedHashSet<>(List.of("realm:admin", "realm-management.realm-admin"));
        supers.addAll(config.readList(SUPER_ROLES));
        return switch (checkId) {
            case GroupScopeCheck.ID -> new PolicySettings(config.readEnum(SCOPE, GroupScope.class),
                    config.readString(MANAGER_ROLE), false, SelfProtection.OFF, Map.of(), denyAnonymous, supers);
            case NoEscalationCheck.ID ->
                new PolicySettings(GroupScope.OFF, null, true, SelfProtection.OFF, Map.of(), denyAnonymous, supers);
            case SelfProtectionCheck.ID ->
                new PolicySettings(GroupScope.OFF, null, false, config.readEnum(MODE, SelfProtection.class),
                        tools(config.readList(TOOLS), config.key(TOOLS.name())), denyAnonymous, supers);
            default -> throw new IllegalArgumentException("not a built-in policy check: " + checkId);
        };
    }

    /**
     * Problem code: a {@code tools} entry that is not {@code <tool>=<user argument>};
     * args {@code key}, {@code value}.
     */
    public static final String INVALID_TOOL_ENTRY = "access-check.self-protection.invalid-tool-entry";

    private static Map<String, String> tools(List<String> entries, String where) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String entry : entries) {
            int eq = entry.indexOf('=');
            if (eq <= 0) {
                throw new ConfigValueException(ConfigProblem
                    .error(INVALID_TOOL_ENTRY,
                            where + ": entries are <tool>=<user argument> (an empty argument removes a built-in"
                                    + " tool), not '" + entry + "'",
                            TOOLS.name())
                    .withArg("key", where)
                    .withArg("value", entry));
            }
            out.put(entry.substring(0, eq).trim(), entry.substring(eq + 1).trim());
        }
        return out;
    }

    public boolean enabled() {
        return groupScope != GroupScope.OFF || noEscalation || selfProtection != SelfProtection.OFF;
    }
}
