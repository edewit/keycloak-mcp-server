package com.github.thomasdarimont.keycloak.mcp.server.policies;

import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;

/**
 * Shared logic of the two checks: anonymous handling, resolving the caller in the target
 * realm, super roles.
 */
final class CallerContext {

    private CallerContext() {
    }

    /** Empty = proceed with the check; present = decision already made (skip or deny). */
    static Optional<AccessCheck.Decision> preflight(AccessCheck.Context ctx, PolicySettings settings) {
        Caller caller = ctx.caller();
        if (caller.isAnonymous()) {
            return Optional.of(settings.denyAnonymous()
                    ? AccessCheck.Decision.deny("caller_required",
                            ctx.tool().name() + " requires an authenticated caller on this server.")
                    : AccessCheck.Decision.allow());
        }
        for (String superRole : settings.superRoles()) {
            if (caller.hasRole(superRole)) {
                return Optional.of(AccessCheck.Decision.allow());
            }
        }
        if (caller.realm() != null && ctx.realm() != null && !caller.realm().equals(ctx.realm())) {
            return Optional.of(AccessCheck.Decision.deny("caller_foreign_realm", "Caller '" + caller.name()
                    + "' belongs to realm '" + caller.realm() + "', not to '" + ctx.realm() + "'."));
        }
        return Optional.empty();
    }

    static String callerUserId(RealmDirectory directory, AccessCheck.Context ctx) {
        Caller caller = ctx.caller();
        Optional<String> id = directory.userId(ctx.realm(), caller.subject());
        if (id.isEmpty() && caller.name() != null) {
            id = directory.userId(ctx.realm(), caller.name());
        }
        return id.orElse(null);
    }

    static AccessCheck.Decision unknownCaller(AccessCheck.Context ctx) {
        return AccessCheck.Decision.deny("caller_unknown",
                "Caller '" + ctx.caller().name() + "' is not a user of realm '" + ctx.realm() + "'.");
    }

    static boolean hasEffectiveRole(RealmDirectory directory, String realm, String userId, Caller caller,
            String roleRef) {
        if (roleRef == null || roleRef.isBlank()) {
            return true;
        }
        return caller.hasRole(roleRef) || directory.effectiveRoles(realm, userId).contains(roleRef);
    }

    static Set<String> missing(Set<String> required, Set<String> granted) {
        Set<String> missing = new java.util.TreeSet<>(required);
        missing.removeAll(granted);
        return missing;
    }
}
