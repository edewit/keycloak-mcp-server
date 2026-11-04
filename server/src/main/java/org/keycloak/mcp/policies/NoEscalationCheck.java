package org.keycloak.mcp.policies;

import java.util.Optional;
import java.util.Set;

import org.keycloak.mcp.spi.AccessCheck;

/**
 * Privilege ceiling: a caller may only grant roles (directly, via client roles, group
 * mappings or group membership) that lie within their own effective roles, and may only
 * manage users whose effective roles lie within their own. Self-grants are refused.
 */
public final class NoEscalationCheck implements AccessCheck {

    static final Set<String> GRANT_TOOLS = Set.of("keycloak_user_role_assign", "keycloak_user_client_role_assign",
            "keycloak_group_role_assign", "keycloak_group_member_add");
    /** tools that act on a target user: the target must not outrank the caller */
    static final java.util.Map<String, String> USER_ARG = java.util.Map.ofEntries(
            java.util.Map.entry("keycloak_user_set_enabled", "id"), java.util.Map.entry("keycloak_user_update", "id"),
            java.util.Map.entry("keycloak_user_delete", "id"),
            java.util.Map.entry("keycloak_user_reset_password", "id"),
            java.util.Map.entry("keycloak_user_send_action_email", "id"),
            java.util.Map.entry("keycloak_user_logout", "id"),
            java.util.Map.entry("keycloak_user_role_assign", "userId"),
            java.util.Map.entry("keycloak_user_role_unassign", "userId"),
            java.util.Map.entry("keycloak_user_client_role_assign", "userId"),
            java.util.Map.entry("keycloak_user_client_role_unassign", "userId"),
            java.util.Map.entry("keycloak_group_member_add", "userId"),
            java.util.Map.entry("keycloak_group_member_remove", "userId"));

    private final java.util.function.Function<Context, RealmDirectory> directories;
    private final PolicySettings settings;

    public NoEscalationCheck(RealmDirectory directory, PolicySettings settings) {
        this(ctx -> directory, settings);
    }

    public NoEscalationCheck(java.util.function.Function<Context, RealmDirectory> directories,
            PolicySettings settings) {
        this.directories = directories;
        this.settings = settings;
    }

    @Override
    public Decision check(Context ctx) {
        String tool = ctx.tool().name();
        if (!settings.noEscalation() || (!GRANT_TOOLS.contains(tool) && !USER_ARG.containsKey(tool))) {
            return Decision.allow();
        }
        Optional<Decision> pre = CallerContext.preflight(ctx, settings);
        if (pre.isPresent()) {
            return pre.get();
        }
        RealmDirectory directory = directories.apply(ctx);
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return CallerContext.unknownCaller(ctx);
        }
        Set<String> mine = directory.effectiveRoles(ctx.realm(), callerId);

        // 1. the target user must not outrank the caller
        String userArg = USER_ARG.get(tool);
        if (userArg != null && ctx.arg(userArg) != null) {
            Optional<String> targetId = directory.userId(ctx.realm(), ctx.arg(userArg));
            if (targetId.isPresent()) {
                if (targetId.get().equals(callerId) && GRANT_TOOLS.contains(tool)) {
                    return Decision.deny("self_grant", "You cannot grant privileges to yourself.");
                }
                Set<String> missing = CallerContext.missing(directory.effectiveRoles(ctx.realm(), targetId.get()),
                        mine);
                if (!missing.isEmpty()) {
                    return Decision.deny("target_outranks_caller",
                            "The target user holds roles you do not: " + missing + ".");
                }
            }
        }
        // 2. what is being granted must be within the caller's roles
        if (GRANT_TOOLS.contains(tool)) {
            Set<String> granting = switch (tool) {
                case "keycloak_user_role_assign", "keycloak_group_role_assign" ->
                    directory.roleClosure(ctx.realm(), "realm:" + ctx.arg("role"));
                case "keycloak_user_client_role_assign" ->
                    directory.roleClosure(ctx.realm(), ctx.arg("clientId") + "." + ctx.arg("role"));
                case "keycloak_group_member_add" -> directory.groupPath(ctx.realm(), ctx.arg("groupId"))
                    .map(p -> directory.groupRoles(ctx.realm(), p))
                    .orElse(Set.of());
                default -> Set.of();
            };
            Set<String> missing = CallerContext.missing(granting, mine);
            if (!missing.isEmpty()) {
                return Decision.deny("privilege_escalation",
                        "This would grant roles you do not hold yourself: " + missing + ".");
            }
        }
        return Decision.allow();
    }
}
