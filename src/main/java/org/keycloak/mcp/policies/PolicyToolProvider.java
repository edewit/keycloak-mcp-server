package org.keycloak.mcp.policies;

import java.util.List;

import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.spi.AccessCheck;
import org.keycloak.mcp.spi.ToolProvider;
import org.keycloak.mcp.spi.ToolProviderContext;

/**
 * Built-in policies: no tools, only access checks. Configure with {@code kc-mcp.spi.policies.*}:
 * {@code group-scope=off|group|organization}, {@code manager-role=realm:group-manager}, {@code no-escalation=true},
 * {@code anonymous=allow|deny}, {@code super-roles=...}. Both checks only act for authenticated callers unless
 * {@code anonymous=deny}.
 */
public class PolicyToolProvider implements ToolProvider {

    private java.util.function.Function<AccessCheck.Context, RealmDirectory> directories;
    private PolicySettings settings = PolicySettings.DISABLED;

    public PolicyToolProvider() {
    }

    /** For tests: fixed directory and settings. */
    public PolicyToolProvider(RealmDirectory directory, PolicySettings settings) {
        this.directories = ctx -> directory;
        this.settings = settings;
    }

    @Override
    public String id() {
        return "policies";
    }

    @Override
    public String displayName() {
        return "Built-in access policies";
    }

    @Override
    public String description() {
        return "Group / organization scoping of group management and a no-privilege-escalation rule.";
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public void init(ToolProviderContext context) {
        if (directories == null) {
            java.util.Map<String, RealmDirectory> cache = new java.util.concurrent.ConcurrentHashMap<>();
            directories = ctx -> {
                if (ctx.keycloak() != null && ctx.keycloak().isDelegated()) {
                    // delegated call: look things up with the caller's own token, the server may have none
                    return new KeycloakDirectory(ctx.keycloak());
                }
                String system = ctx.system();
                return cache.computeIfAbsent(system == null ? "" : system,
                        s -> new KeycloakDirectory(s.isEmpty() ? context.keycloak() : context.keycloak(s)));
            };
            settings = PolicySettings.from(context.config());
        }
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of();
    }

    @Override
    public List<AccessCheck> accessChecks(ToolProviderContext context) {
        if (!settings.enabled()) {
            return List.of();
        }
        return List.of(new GroupScopeCheck(directories, settings), new NoEscalationCheck(directories, settings));
    }
}
