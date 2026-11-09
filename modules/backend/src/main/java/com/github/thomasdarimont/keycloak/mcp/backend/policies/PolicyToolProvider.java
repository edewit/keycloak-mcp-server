package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * Built-in policies: no tools, only access checks. Configure with
 * {@code kc-mcp.spi.tools.policies.*}: {@code group-scope=off|group|organization},
 * {@code manager-role=realm:group-manager}, {@code no-escalation=true},
 * {@code self-protection=reject|confirm|off},
 * {@code self-protection-tools=<tool>=<arg>,...}, {@code anonymous=allow|deny},
 * {@code super-roles=...}. The checks only act for authenticated callers unless
 * {@code anonymous=deny}.
 */
@AutoService(ToolProvider.class)
public class PolicyToolProvider implements ToolProvider {

    private Function<AccessCheck.Context, RealmDirectory> directories;
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
        return "Group / organization scoping of group management, a no-privilege-escalation rule and the"
                + " protection of the caller's own account.";
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public void init(ToolProviderContext context) {
        if (directories == null) {
            // client ids are stable, the directory of one evaluation remembers the rest
            Map<String, Map<String, String>> clientIds = new ConcurrentHashMap<>();
            directories = ctx -> (RealmDirectory) ctx.attributes()
                .computeIfAbsent(KeycloakDirectory.class.getName(), k -> {
                    String system = ctx.system() == null ? "" : ctx.system();
                    // a delegated call looks things up with the caller's own token,
                    // the server may have none
                    KeycloakAdmin kc = ctx.keycloak() != null && ctx.keycloak().isDelegated() ? ctx.keycloak()
                            : system.isEmpty() ? context.keycloak() : context.keycloak(system);
                    return new KeycloakDirectory(kc, clientIds.computeIfAbsent(system, s -> new ConcurrentHashMap<>()));
                });
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
        return List.of(new GroupScopeCheck(directories, settings), new NoEscalationCheck(directories, settings),
                new SelfProtectionCheck(directories, settings));
    }
}
