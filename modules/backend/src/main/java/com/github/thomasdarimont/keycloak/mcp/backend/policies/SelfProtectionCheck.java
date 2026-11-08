package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;

/**
 * The caller cannot cut themselves off through this server, whatever their rank: deleting
 * or disabling their own account is caught outright, and removing their own roles or
 * group memberships when that would take their administrative access away
 * ({@code realm:admin}, a {@code realm-management} or master {@code <realm>-realm} role,
 * a configured super role, or a group granting one). Leaving a test group or dropping an
 * ordinary role stays possible: someone else can give it back. Caught means refused
 * ({@code self-protection=reject}) or handed to the human for their own confirmation
 * ({@code confirm}: elicitation or a confirmer that asks them, never the model's flag).
 * Super roles do not bypass this check, an administrator locking themselves out is
 * exactly the case. A caller of another realm cannot be the target, so the check does not
 * apply to them. {@code self-protection-tools} adds tools of other providers that act on
 * a user (caught whenever the user is the caller) or removes built-in ones.
 */
public final class SelfProtectionCheck implements AccessCheck {

    /** built-in tools that act on a user, with the argument naming them */
    static final Map<String, String> BUILT_IN = Map.of("keycloak_user_delete", "id", "keycloak_user_set_enabled", "id",
            "keycloak_user_update", "id", "keycloak_user_role_unassign", "userId", "keycloak_user_client_role_unassign",
            "userId", "keycloak_group_member_remove", "userId");

    private final Function<Context, RealmDirectory> directories;
    private final PolicySettings settings;
    private final Map<String, String> userArgs;

    public SelfProtectionCheck(RealmDirectory directory, PolicySettings settings) {
        this(ctx -> directory, settings);
    }

    public SelfProtectionCheck(Function<Context, RealmDirectory> directories, PolicySettings settings) {
        this.directories = directories;
        this.settings = settings;
        Map<String, String> args = new HashMap<>(BUILT_IN);
        settings.selfProtectionTools().forEach((tool, arg) -> {
            if (arg == null || arg.isBlank()) {
                args.remove(tool);
            }
            else {
                args.put(tool, arg);
            }
        });
        this.userArgs = Map.copyOf(args);
    }

    /**
     * The guarded tools and the argument naming the user, after the configured overrides.
     */
    public Map<String, String> userArgs() {
        return userArgs;
    }

    @Override
    public Decision check(Context ctx) {
        String tool = ctx.tool().name();
        String userArg = userArgs.get(tool);
        Caller caller = ctx.caller();
        if (settings.selfProtection() == PolicySettings.SelfProtection.OFF || userArg == null || caller.isAnonymous()
                || ctx.arg(userArg) == null) {
            return Decision.allow();
        }
        if (caller.realm() != null && ctx.realm() != null && !caller.realm().equals(ctx.realm())) {
            return Decision.allow();
        }
        String target = ctx.arg(userArg);
        switch (tool) {
            case "keycloak_user_delete" -> {
                if (isCaller(ctx, target)) {
                    return refuse(caller, "delete your own account");
                }
            }
            case "keycloak_user_set_enabled", "keycloak_user_update" -> {
                if (disables(ctx) && isCaller(ctx, target)) {
                    return refuse(caller, "disable your own account");
                }
            }
            case "keycloak_user_role_unassign", "keycloak_user_client_role_unassign" -> {
                String key = "keycloak_user_role_unassign".equals(tool) ? "realm:" + ctx.arg("role")
                        : ctx.arg("clientId") + "." + ctx.arg("role");
                if (isCaller(ctx, target)) {
                    Set<String> granted = directories.apply(ctx).roleClosure(ctx.realm(), key);
                    Set<String> admin = administrative(granted.isEmpty() ? Set.of(key) : granted);
                    if (!admin.isEmpty()) {
                        return refuse(caller, "remove your own administrative access (" + admin + ")");
                    }
                }
            }
            case "keycloak_group_member_remove" -> {
                if (isCaller(ctx, target)) {
                    RealmDirectory directory = directories.apply(ctx);
                    Set<String> admin = directory.groupPath(ctx.realm(), ctx.arg("groupId"))
                        .map(path -> administrative(directory.groupRoles(ctx.realm(), path)))
                        .orElse(Set.of());
                    if (!admin.isEmpty()) {
                        return refuse(caller, "leave a group that grants your administrative access (" + admin + ")");
                    }
                }
            }
            default -> {
                // a configured tool of another provider: caught whenever it acts on the
                // caller
                if (isCaller(ctx, target)) {
                    return refuse(caller, "act on your own account with " + tool);
                }
            }
        }
        return Decision.allow();
    }

    /**
     * The configured answer: a refusal, or the demand that the human confirm it
     * themselves.
     */
    private Decision refuse(Caller caller, String what) {
        if (settings.selfProtection() == PolicySettings.SelfProtection.CONFIRM) {
            return Decision.confirm("self_protection", "This would " + what + " ('" + caller.name()
                    + "'): only you can confirm that, through this client or on your device.");
        }
        return Decision.deny("self_protection", "This would " + what + " ('" + caller.name()
                + "'). The server refuses that whatever your roles; another administrator has to do it.");
    }

    /**
     * The administrative roles among role keys: the realm's admin, Keycloak's
     * {@code realm-management} roles, the master realm's {@code <realm>-realm} roles and
     * the configured super roles.
     */
    Set<String> administrative(Set<String> roleKeys) {
        Set<String> admin = new TreeSet<>();
        for (String key : roleKeys) {
            int dot = key.indexOf('.');
            String client = key.startsWith("realm:") || dot < 0 ? null : key.substring(0, dot);
            if ("realm:admin".equals(key) || "realm-management".equals(client)
                    || (client != null && client.endsWith("-realm")) || settings.superRoles().contains(key)) {
                admin.add(key);
            }
        }
        return admin;
    }

    private static boolean disables(Context ctx) {
        Object enabled = ctx.args().get("enabled");
        return enabled != null && "false".equalsIgnoreCase(String.valueOf(enabled));
    }

    /** By subject or username first, then resolved in the realm when the forms differ. */
    private boolean isCaller(Context ctx, String target) {
        Caller caller = ctx.caller();
        if (target.equals(caller.subject()) || (caller.name() != null && target.equalsIgnoreCase(caller.name()))) {
            return true;
        }
        RealmDirectory directory = directories.apply(ctx);
        Optional<String> targetId = directory.userId(ctx.realm(), target);
        String callerId = CallerContext.callerUserId(directory, ctx);
        return targetId.isPresent() && targetId.get().equals(callerId);
    }
}
