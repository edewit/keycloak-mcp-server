package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;

/**
 * One of the built-in policy checks as the access check chain runs it: the settings of
 * each call ({@link Context#settings()}: the server's
 * {@code kc-mcp.spi.access-check.<id>.*} with the system's and the realm's entry over
 * them) become {@link PolicySettings}, and the check built for those settings decides.
 * One check per distinct settings, kept: the settings of a server's systems and realms
 * are few.
 */
final class ConfiguredPolicyCheck implements AccessCheck {

    private final String id;
    private final String displayName;
    private final boolean enabledByDefault;
    private final Function<PolicySettings, AccessCheck> factory;
    private final Map<PolicySettings, AccessCheck> bySettings = new ConcurrentHashMap<>();

    ConfiguredPolicyCheck(String id, String displayName, boolean enabledByDefault,
            Function<PolicySettings, AccessCheck> factory) {
        this.id = id;
        this.displayName = displayName;
        this.enabledByDefault = enabledByDefault;
        this.factory = factory;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String displayName() {
        return displayName;
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public boolean enabledByDefault() {
        return enabledByDefault;
    }

    @Override
    public Decision check(Context ctx) {
        PolicySettings settings;
        try {
            settings = PolicySettings.forCheck(id, ctx.settings());
        }
        catch (IllegalArgumentException e) {
            // settings that do not parse protect nothing: refuse rather than run without
            return Decision.deny("access_check_failed",
                    "The settings of the access check '" + id + "' for this system are invalid: " + e.getMessage());
        }
        return bySettings.computeIfAbsent(settings, factory).check(ctx);
    }

    /** The check for one set of settings, for tests and the startup log. */
    AccessCheck forSettings(PolicySettings settings) {
        return bySettings.computeIfAbsent(settings, factory);
    }
}
