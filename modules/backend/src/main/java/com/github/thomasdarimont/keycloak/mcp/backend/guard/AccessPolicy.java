package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.Requirement;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.quarkus.runtime.Startup;

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
@Startup
@ApplicationScoped
public class AccessPolicy {

    private static final Logger LOG = Logger.getLogger(AccessPolicy.class);

    /**
     * Points the model at the tool that explains the current permissions instead of
     * retrying.
     */
    public static final String WHOAMI_HINT = "Do not retry; tell the user which role is missing. "
            + "Call whoami to see what the current caller may do.";

    /** The same for users who do not run the server: no configuration details. */
    public static final String UNSUPPORTED_HINT_USER = "Do not retry; this is not possible on this Keycloak server. "
            + "Tell the user so in plain words and that a Keycloak administrator can change it; do not list"
            + " configuration options.";

    /** Points the model at the server side cause instead of retrying. */
    public static final String UNSUPPORTED_HINT = "Do not retry; the Keycloak server lacks the feature or version. "
            + "Tell the user what is missing and how an administrator fixes it (howToFix); whoami shows the server"
            + " version.";

    private final boolean readOnly;
    private final Set<String> allowedRealms;
    private final java.util.function.Function<String, Set<String>> allowedRealmsBySystem;
    private final Set<String> allowedTools;
    private final Set<String> deniedTools;
    private final Set<Category> allowedCategories;
    private final RoleDiscovery roles;
    private final CapabilityDiscovery capabilities;
    private final Explanations explanations;
    private final List<AccessCheck> globalChecks;

    @Inject
    public AccessPolicy(McpServerConfig config, RoleDiscovery roles, CapabilityDiscovery capabilities,
            DefaultExtensionRegistry registry, KeycloakSystems systems) {
        this(config.readOnly(), config.allowedRealms().orElse(List.of()), config.allowedTools().orElse(List.of()),
                config.deniedTools().orElse(List.of()), config.allowedCategories().orElse(List.of()), roles,
                collectChecks(registry),
                name -> systems.find(name).map(a -> a.system().allowedRealms()).orElse(Set.of()), capabilities,
                config.explanations());
    }

    /** The providers' checks first, then the ones registered on their own. */
    private static List<AccessCheck> collectChecks(DefaultExtensionRegistry registry) {
        List<AccessCheck> checks = new ArrayList<>(registry.accessChecks());
        for (AccessCheck c : registry.extensions(AccessCheck.class)) {
            LOG.infof("Access check '%s' registered (%s)", c.id(), c.getClass().getName());
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
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks,
                allowedRealmsBySystem, null);
    }

    /**
     * @param capabilities version and features per system for the tools' requirements;
     * {@code null} leaves them unchecked
     */
    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, java.util.function.Function<String, Set<String>> allowedRealmsBySystem,
            CapabilityDiscovery capabilities) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks,
                allowedRealmsBySystem, capabilities, Explanations.AUTO);
    }

    /**
     * @param explanations who reads the explanations of refusals; see
     * {@link Explanations}
     */
    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, java.util.function.Function<String, Set<String>> allowedRealmsBySystem,
            CapabilityDiscovery capabilities, Explanations explanations) {
        this.readOnly = readOnly;
        this.capabilities = capabilities;
        this.explanations = explanations == null ? Explanations.AUTO : explanations;
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
        ServerCapabilities caps = capabilities(system);
        Optional<Requirement> unmet = firstUnmet(spec, caps);
        if (unmet.isPresent()) {
            Explanations who = explanationsFor(granted, delegated);
            String message = spec.name() + " " + unmet.get().unmet(caps, who).orElseThrow()
                    + (system != null ? " (system '" + system + "')" : "");
            List<String> requirements = spec.requires().stream().map(Requirement::describe).toList();
            return Optional.of(who == Explanations.ADMINS
                    ? ToolResult.error("unsupported", message, "requirements", requirements, "howToFix",
                            unmet.get().guidance(), "hint", UNSUPPORTED_HINT)
                    : ToolResult.error("unsupported", message, "requirements", requirements, "hint",
                            UNSUPPORTED_HINT_USER));
        }
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
     * Version and features of a system as currently cached or read;
     * {@link ServerCapabilities#UNKNOWN} when checks are off.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     */
    public ServerCapabilities capabilities(String system) {
        if (capabilities == null) {
            return ServerCapabilities.UNKNOWN;
        }
        return system == null ? capabilities.get() : capabilities.get(system);
    }

    /** The first unmet requirement of the tool against these capabilities. */
    public static Optional<String> unsupported(ToolSpec spec, ServerCapabilities caps) {
        return firstUnmet(spec, caps).flatMap(r -> r.unmet(caps));
    }

    /** The same, worded for the explanations. */
    public static Optional<String> unsupported(ToolSpec spec, ServerCapabilities caps, Explanations explanations) {
        return firstUnmet(spec, caps).flatMap(r -> r.unmet(caps, explanations));
    }

    /**
     * Who gets the explanation: the configured explanations, or with {@code auto} the
     * admin wording unless the caller acts on their own behalf without a master admin or
     * {@code realm-admin} role.
     */
    public Explanations explanationsFor(GrantedRoles granted, boolean delegated) {
        if (explanations != Explanations.AUTO) {
            return explanations;
        }
        if (!delegated || granted == null || !granted.known() || granted.superAdmin()) {
            return Explanations.ADMINS;
        }
        boolean realmAdmin = granted.byRealm().values().stream().anyMatch(r -> r.contains("realm-admin"));
        return realmAdmin ? Explanations.ADMINS : Explanations.USERS;
    }

    /** The first requirement of the tool these capabilities do not meet. */
    public static Optional<Requirement> firstUnmet(ToolSpec spec, ServerCapabilities caps) {
        for (Requirement r : spec.requires()) {
            if (r.unmet(caps).isPresent()) {
                return Optional.of(r);
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
