package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * Built-in policies: no tools, three access checks, {@code group-scope},
 * {@code no-escalation} and {@code self-protection}. Each is configured as an access
 * check ({@code kc-mcp.spi.access-check.<id>.*}, per system and realm in their
 * {@code access} blocks) and reads its settings per call ({@link ConfiguredPolicyCheck}).
 * The settings of old, {@code kc-mcp.spi.tools.policies.*} besides {@code enabled}, stop
 * the start with their replacements ({@link #REPLACED}).
 */
@AutoService(ToolProvider.class)
public class PolicyToolProvider implements ToolProvider {

    /** The settings of old and what replaces them. */
    static final Map<String, String> REPLACED = Map.of("group-scope",
            "kc-mcp.spi.access-check.group-scope.default=on and kc-mcp.spi.access-check.group-scope.scope=group|organization",
            "manager-role", "kc-mcp.spi.access-check.group-scope.manager-role", "no-escalation",
            "kc-mcp.spi.access-check.no-escalation.default=on|off", "self-protection",
            "kc-mcp.spi.access-check.self-protection.mode=reject|confirm, or its default=off", "self-protection-tools",
            "kc-mcp.spi.access-check.self-protection.tools", "anonymous",
            "kc-mcp.spi.access-check.<group-scope|no-escalation|self-protection>.anonymous", "super-roles",
            "kc-mcp.spi.access-check.<group-scope|no-escalation|self-protection>.super-roles");

    private Function<AccessCheck.Context, RealmDirectory> directories;
    /** Fixed settings of tests; {@code null}: per call. */
    private PolicySettings fixed;

    public PolicyToolProvider() {
    }

    /** For tests: fixed directory and settings. */
    public PolicyToolProvider(RealmDirectory directory, PolicySettings settings) {
        this.directories = ctx -> directory;
        this.fixed = settings;
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
        }
        refuseOldSettings(context.config());
    }

    /**
     * The settings of {@code kc-mcp.spi.tools.policies.*} are gone; one still set stops
     * the start, so that a rule an operator relied on is not quietly dropped.
     */
    static void refuseOldSettings(ProviderConfig config) {
        java.util.List<String> found = new java.util.ArrayList<>();
        for (String key : new java.util.TreeSet<>(config.keys())) {
            if (REPLACED.containsKey(key)) {
                found.add("kc-mcp.spi.tools.policies." + key + " -> " + REPLACED.get(key));
            }
        }
        if (!found.isEmpty()) {
            throw new IllegalStateException("The built-in policies are access checks now; replace "
                    + String.join("; ", found) + " (docs/access-checks.md)");
        }
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of();
    }

    @Override
    public List<AccessCheck> accessChecks(ToolProviderContext context) {
        if (fixed != null) {
            if (!fixed.enabled()) {
                return List.of();
            }
            return List.of(new GroupScopeCheck(directories, fixed), new NoEscalationCheck(directories, fixed),
                    new SelfProtectionCheck(directories, fixed));
        }
        Function<AccessCheck.Context, RealmDirectory> dirs = directories;
        // the group scope only where it is asked for; the other two everywhere unless
        // switched off
        return List.of(
                new ConfiguredPolicyCheck(GroupScopeCheck.ID, "Group scope", false, s -> new GroupScopeCheck(dirs, s)),
                new ConfiguredPolicyCheck(NoEscalationCheck.ID, "No privilege escalation", true,
                        s -> new NoEscalationCheck(dirs, s)),
                new ConfiguredPolicyCheck(SelfProtectionCheck.ID, "Self-protection", true,
                        s -> new SelfProtectionCheck(dirs, s)));
    }
}
