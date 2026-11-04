package org.keycloak.mcp.server.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.KeycloakSystems;
import org.keycloak.mcp.server.catalog.ToolCatalog;
import org.keycloak.mcp.server.spi.ToolProviderRegistry;
import org.keycloak.mcp.spi.AccessCheck;
import org.keycloak.mcp.spi.Delegation;
import org.keycloak.mcp.spi.GrantedRoles;

/**
 * Who may do what:
 * <ul>
 * <li>static: READ_ONLY, allowed/denied tools, allowed categories, ALLOWED_REALMS
 * (decided at startup),</li>
 * <li>dynamic: the {@code realm-management} roles the server's token actually holds
 * ({@link RoleDiscovery}).</li>
 * </ul>
 * {@link #permits} is the static part and decides registration; {@link #visible} adds
 * roles for listing and search; {@link #forbids} is the per-call check with the resolved
 * realm: realm allow-list, roles, delegation, global {@link AccessCheck}s, then the
 * tool's own checks.
 */
@ApplicationScoped
public class AccessPolicy {

    /**
     * Points the model at the tool that explains the current permissions instead of
     * retrying.
     */
    public static final String WHOAMI_HINT = "Do not retry; tell the user which role is missing. "
            + "Call whoami to see what the current caller may do.";

    private final boolean readOnly;
    private final Set<String> allowedRealms;
    private final java.util.function.Function<String, Set<String>> allowedRealmsBySystem;
    private final Set<String> allowedTools;
    private final Set<String> deniedTools;
    private final Set<Category> allowedCategories;
    private final RoleDiscovery roles;
    private final List<AccessCheck> globalChecks;

    @Inject
    public AccessPolicy(McpServerConfig config, RoleDiscovery roles, ToolProviderRegistry registry,
            Instance<AccessCheck> cdiChecks, KeycloakSystems systems) {
        this(config.readOnly(), config.allowedRealms().orElse(List.of()), config.allowedTools().orElse(List.of()),
                config.deniedTools().orElse(List.of()), config.allowedCategories().orElse(List.of()), roles,
                collectChecks(registry, cdiChecks),
                name -> systems.find(name).map(a -> a.system().allowedRealms()).orElse(Set.of()));
    }

    private static List<AccessCheck> collectChecks(ToolProviderRegistry registry, Instance<AccessCheck> cdiChecks) {
        List<AccessCheck> checks = new ArrayList<>(registry.accessChecks());
        for (AccessCheck c : cdiChecks) {
            checks.add(c);
        }
        return checks;
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms) {
        this(readOnly, allowedRealms, List.of(), List.of(), List.of(), null, List.of());
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, List.of());
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks, null);
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, java.util.function.Function<String, Set<String>> allowedRealmsBySystem) {
        this.readOnly = readOnly;
        this.allowedRealms = clean(allowedRealms);
        this.allowedRealmsBySystem = allowedRealmsBySystem;
        this.allowedTools = clean(allowedTools).stream().map(AccessPolicy::shortName).collect(Collectors.toSet());
        this.deniedTools = clean(deniedTools).stream().map(AccessPolicy::shortName).collect(Collectors.toSet());
        this.allowedCategories = clean(allowedCategories).stream()
            .map(Category::parse)
            .filter(c -> c != null)
            .collect(Collectors.toSet());
        this.roles = roles;
        this.globalChecks = List.copyOf(globalChecks == null ? List.of() : globalChecks);
    }

    /** Tool names in config may omit the {@code keycloak_} prefix. */
    static String shortName(String name) {
        String n = ToolCatalog.normalize(name);
        return n.startsWith("keycloak_") ? n.substring("keycloak_".length()) : n;
    }

    private static Set<String> clean(List<String> values) {
        return values == null ? Set.of()
                : values.stream().map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    public boolean readOnly() {
        return readOnly;
    }

    /**
     * Static policy: whether the tool may exist on this server at all (registration,
     * search, execution).
     */
    public boolean permits(ToolSpec spec) {
        if (readOnly && !spec.isReadOnly()) {
            return false;
        }
        String name = shortName(spec.name());
        if (deniedTools.contains(name)) {
            return false;
        }
        if (!allowedTools.isEmpty() && !allowedTools.contains(name)) {
            return false;
        }
        return allowedCategories.isEmpty() || allowedCategories.contains(spec.category());
    }

    /**
     * Static policy plus roles as currently known in any system, without blocking
     * (tools/list filter).
     */
    public boolean visible(ToolSpec spec) {
        return permits(spec) && (roles == null || roles.anySystemPeek(g -> g.permitsAnyRealm(spec.requiredRoles())));
    }

    /**
     * Static policy plus roles, discovering them if necessary (used by search_tools and
     * suggestions).
     */
    public boolean visibleNow(ToolSpec spec) {
        return permits(spec) && (roles == null || roles.anySystem(g -> g.permitsAnyRealm(spec.requiredRoles())));
    }

    /**
     * Per-call check without arguments or caller (static policy, realm and roles only).
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String realm) {
        return forbids(spec, null, realm, Map.of(), InvocationContext.none());
    }

    public Optional<ToolResult> forbids(ToolSpec spec, String realm, Map<String, Object> args, InvocationContext ctx) {
        return forbids(spec, null, realm, args, ctx);
    }

    /**
     * Per-call check once system, realm and the validated arguments are known; empty when
     * the call may proceed.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String system, String realm, Map<String, Object> args,
            InvocationContext ctx) {
        return forbids(spec, system, realm, args, ctx, null);
    }

    /**
     * @param admin the admin client the call will run with (the caller's own under
     * delegation), handed to the access checks; {@code null} when unknown
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String system, String realm, Map<String, Object> args,
            InvocationContext ctx, KeycloakAdmin admin) {
        if (!permits(spec)) {
            if (readOnly && !spec.isReadOnly()) {
                return Optional.of(ToolResult.error("read_only_mode", "This server runs in read-only mode; "
                        + spec.name() + " is a " + spec.level().name().toLowerCase() + " operation."));
            }
            return Optional.of(ToolResult.error("tool_not_allowed", spec.name() + " is disabled on this server."));
        }
        if (realm != null && !realmAllowed(system, realm)) {
            return Optional.of(ToolResult.error("realm_not_allowed",
                    "Realm '" + realm + "' is not allowed" + (system != null ? " in system '" + system + "'." : "."),
                    "allowed", List.copyOf(allowedRealms(system))));
        }
        boolean delegated = ctx.caller().delegated();
        GrantedRoles granted = granted(system, ctx);
        if (granted != null && realm != null) {
            String who = delegated ? "caller '" + ctx.caller().name() + "' has" : "the server's credentials have";
            // an unknown server token disables filtering; a caller token without any
            // admin role simply cannot act
            if (!granted.reaches(realm) || (delegated && !granted.known())) {
                return Optional.of(ToolResult.error(
                        "forbidden", Character.toUpperCase(who.charAt(0)) + who.substring(1)
                                + " no admin roles in realm '" + realm + "'.",
                        "realmsWithRoles", List.copyOf(granted.realms()), "hint", WHOAMI_HINT));
            }
            Set<String> missing = granted.missing(realm, spec.requiredRoles());
            if (!missing.isEmpty()) {
                return Optional.of(ToolResult.error("forbidden",
                        spec.name() + " needs the realm-management role(s) " + missing + " in realm '" + realm
                                + "', which "
                                + (delegated ? "caller '" + ctx.caller().name() + "' lacks."
                                        : "the server's credentials lack."),
                        "missingRoles", List.copyOf(missing), "hint", WHOAMI_HINT));
            }
        }
        if (delegated && spec.delegation() == Delegation.FORBIDDEN) {
            return Optional.of(ToolResult.error("delegation_not_allowed",
                    spec.name() + " cannot be used on behalf of a user; it needs the server's own service account."));
        }
        if (!delegated && spec.delegation() == Delegation.REQUIRED) {
            return Optional.of(ToolResult.error("delegation_required",
                    spec.name() + " may only run on behalf of an authenticated user."));
        }
        if (!globalChecks.isEmpty() || !spec.accessChecks().isEmpty()) {
            AccessCheck.Context context = new AccessCheck.Context(spec, system, realm, args,
                    granted == null ? GrantedRoles.UNKNOWN : granted, ctx.caller(), admin);
            for (AccessCheck check : globalChecks) {
                Optional<ToolResult> denied = evaluate(check, context);
                if (denied.isPresent()) {
                    return denied;
                }
            }
            for (AccessCheck check : spec.accessChecks()) {
                Optional<ToolResult> denied = evaluate(check, context);
                if (denied.isPresent()) {
                    return denied;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Roles that decide a call: the caller's own (parsed from the forwarded token) when
     * the call is delegated, otherwise the server token's as discovered; {@code null}
     * when role checks are off.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     */
    public GrantedRoles granted(String system, InvocationContext ctx) {
        if (ctx.caller().delegated() && ctx.callerToken() != null) {
            return GrantedRoles.fromToken(ctx.callerToken(), ctx.caller().realm());
        }
        if (roles == null) {
            return null;
        }
        return system == null ? roles.get() : roles.get(system);
    }

    private static Optional<ToolResult> evaluate(AccessCheck check, AccessCheck.Context context) {
        AccessCheck.Decision d;
        try {
            d = check.check(context);
        }
        catch (RuntimeException e) {
            return Optional.of(ToolResult.error("access_check_failed", "Access check failed: " + e.getMessage()));
        }
        if (d == null || d.allowed()) {
            return Optional.empty();
        }
        return Optional.of(ToolResult.error(d.code() == null ? "access_denied" : d.code(),
                d.message() == null ? context.tool().name() + " denied by access check" : d.message()));
    }

    public boolean realmAllowed(String realm) {
        return realmAllowed(null, realm);
    }

    public boolean realmAllowed(String system, String realm) {
        Set<String> allowed = allowedRealms(system);
        return allowed.isEmpty() || allowed.contains(realm);
    }

    public Set<String> allowedRealms() {
        return allowedRealms;
    }

    public Set<String> allowedRealms(String system) {
        if (system != null && allowedRealmsBySystem != null) {
            return allowedRealmsBySystem.apply(system);
        }
        return allowedRealms;
    }
}
