package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CheckSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;

/**
 * The access check {@code authorization}: hands tool calls to the
 * {@link AuthorizationEngine}s, as the system's (and realm's) authorization block says.
 * For a call it takes the effective block (the system's with the realm's over it), and
 * <ul>
 * <li>denies it when the block needs an engine this server does not have (installed,
 * switched on, supported) and the call is evaluated, so no system loses its governance to
 * a missing one;</li>
 * <li>asks every engine the block names, or every engine when it names none, whose switch
 * (the block's, else the engine's {@link AuthorizationEngine#evaluatesByDefault}) says
 * the call is evaluated;</li>
 * <li>refuses the call on the first denial, and on an engine that throws; hands it to the
 * human when an engine asks for confirmation.</li>
 * </ul>
 * At startup a configured system that names a missing engine stops the start; the admin
 * API refuses to store one ({@link #check}).
 */
@ApplicationScoped
public class AuthorizationAccessCheck implements AccessCheck {

    private static final Logger LOG = Logger.getLogger(AuthorizationAccessCheck.class);

    public static final String ID = "authorization";

    private final Supplier<List<AuthorizationEngine>> engines;
    private final Function<String, Optional<KeycloakSystem>> systemLookup;
    private final Supplier<List<KeycloakSystem>> staticSystems;
    private volatile List<AuthorizationEngine> found;

    @Inject
    public AuthorizationAccessCheck(Instance<DefaultExtensionRegistry> registry,
            Instance<DefaultKeycloakSystems> systems, McpServerConfig config) {
        // looked up on first use: the registry lists this check among the others
        this(() -> registry.isResolvable() ? registry.get().extensions(AuthorizationEngine.class) : List.of(),
                name -> name == null || !systems.isResolvable() ? Optional.empty()
                        : systems.get().find(name).map(KeycloakAdmin::system),
                () -> {
                    List<KeycloakSystem> out = new ArrayList<>();
                    Presets presets = Presets.fromConfig(config.presets());
                    config.systems().forEach((name, s) -> {
                        if (s.url().isPresent()) {
                            out.add(presets.applyOrBlock(KeycloakSystem.resolve(name, config, s), problem -> {
                            }));
                        }
                    });
                    return out;
                });
    }

    /** For tests: fixed engines and systems. */
    public AuthorizationAccessCheck(Supplier<List<AuthorizationEngine>> engines,
            Function<String, Optional<KeycloakSystem>> systemLookup, Supplier<List<KeycloakSystem>> staticSystems) {
        this.engines = engines;
        this.systemLookup = systemLookup;
        this.staticSystems = staticSystems;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Authorization engines";
    }

    @Override
    public String description() {
        return "Hands tool calls to the authorization engines the system's authorization block names.";
    }

    /** After the server's own checks, before the confirmation. */
    @Override
    public int order() {
        return 2000;
    }

    /** The engines by id. */
    public List<AuthorizationEngine> engines() {
        List<AuthorizationEngine> e = found;
        if (e == null) {
            e = List.copyOf(engines.get());
            found = e;
        }
        return e;
    }

    public Set<String> ids() {
        Set<String> out = new TreeSet<>();
        engines().forEach(e -> out.add(ProviderConfig.configId(e.id())));
        return out;
    }

    /** What a block asks for when it switches evaluation on without naming an engine. */
    static final String ANY_ENGINE = "<any engine>";

    /**
     * The engines a block names that this server does not have; {@link #ANY_ENGINE} for a
     * block that switches evaluation on without naming one, on a server without engines,
     * which would otherwise evaluate nothing.
     */
    public Set<String> missing(AuthorizationSettings authz) {
        Set<String> out = new TreeSet<>(authz.engines().keySet());
        Set<String> have = ids();
        out.removeAll(have);
        if (authz.engines().isEmpty() && authz.enabled().orElse(false) && have.isEmpty()) {
            out.add(ANY_ENGINE);
        }
        return out;
    }

    /**
     * Refuses a system, its own block or a realm's, that names an engine this server does
     * not have, then lets every engine check its settings.
     *
     * @param systemKey see {@link AuthorizationEngine#validate}
     * @throws IllegalArgumentException with what is wrong
     */
    public void check(KeycloakSystem system, boolean systemKey) {
        Set<String> missing = new TreeSet<>(missing(system.authorization()));
        system.realms().values().forEach(r -> missing.addAll(missing(r.authorization())));
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException("The authorization of system '" + system.name()
                    + "' names the engine(s) " + missing + ", which this server does not have; it has " + ids()
                    + " (an engine is an access check extension; it must be installed and switched on)");
        }
        for (AuthorizationEngine engine : engines()) {
            engine.validate(system, systemKey);
        }
    }

    void onStart(@Observes StartupEvent event) {
        ValidationRun.guard(this::runStartupChecks);
    }

    void runStartupChecks() {
        for (KeycloakSystem system : staticSystems.get()) {
            Set<String> missing = new TreeSet<>(missing(system.authorization()));
            system.realms().values().forEach(r -> missing.addAll(missing(r.authorization())));
            if (!missing.isEmpty()) {
                throw new IllegalStateException("kc-mcp.systems." + system.name()
                        + " names the authorization engine(s) " + missing + ", which this server does not have (it has "
                        + ids() + "); install and switch them on, or remove the block");
            }
        }
        if (!ids().isEmpty()) {
            LOG.infof("Authorization engines: %s", ids());
        }
    }

    @Override
    public Decision check(Context ctx) {
        Optional<KeycloakSystem> system = systemLookup.apply(ctx.system());
        AuthorizationSettings authz = planned(ctx) ? fromPlan(ctx.settings())
                : system.map(s -> s.authorization(ctx.realm())).orElse(AuthorizationSettings.NONE);
        Set<String> missing = missing(authz);
        // the missing engine's own default is unknown: count the call as evaluated
        if (!missing.isEmpty() && authz.evaluates(true)) {
            LOG.warnf("System '%s'%s needs the authorization engine(s) %s, which this server does not have; %s denied",
                    ctx.system(), ctx.realm() == null ? "" : " realm '" + ctx.realm() + "'", missing,
                    ctx.tool().name());
            return Decision.deny("authorization_unavailable", "The authorization of system '" + ctx.system()
                    + "' needs an engine this server does not have, so it runs no tool there; nothing was changed."
                    + " An administrator has to install it or change the system's authorization.");
        }
        Decision confirmation = null;
        for (AuthorizationEngine engine : engines()) {
            if (!authz.evaluatedBy(engine.id(), engine.evaluatesByDefault())) {
                continue;
            }
            Decision d;
            try {
                d = engine.decide(new AuthorizationEngine.Request(ctx, system, authz, authz.engine(engine.id())));
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Authorization engine '%s' failed on %s for system '%s'; denied", engine.id(),
                        ctx.tool().name(), ctx.system());
                d = null;
            }
            if (d == null) {
                return Decision.deny("authorization_unavailable",
                        "The authorization service could not decide whether " + ctx.tool().name()
                                + " may run; nothing was changed. Try again later or ask an administrator.");
            }
            if (!d.allowed()) {
                return d;
            }
            if (d.confirmation() && confirmation == null) {
                confirmation = d;
            }
        }
        return confirmation != null ? confirmation : Decision.allow();
    }

    /**
     * Whether the access check chain handed the call over, with this check's effective
     * entry.
     */
    private static boolean planned(Context ctx) {
        return ctx.settings().providerPrefix().endsWith("." + ID + ".");
    }

    /**
     * The effective entry as the access check chain hands it: the server's, the system's
     * and the realm's (or the server's alone, when the operator locked this check), with
     * {@code enabled} when a system or realm switched it itself.
     */
    static AuthorizationSettings fromPlan(ProviderConfig settings) {
        Map<String, String> s = new java.util.LinkedHashMap<>(settings.asMap());
        Optional<Boolean> enabled = Optional.ofNullable(s.remove(AccessCheckChain.ENABLED)).map(Boolean::parseBoolean);
        return AuthorizationSettings.of(new CheckSettings(enabled, Optional.empty(), s));
    }
}
