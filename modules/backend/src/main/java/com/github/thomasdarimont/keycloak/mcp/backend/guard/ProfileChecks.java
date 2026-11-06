package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.Profile;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;

/**
 * Enforces what {@code kc-mcp.profile=shared} promises: callers authenticate against an
 * audience, outbound hosts are listed, the admin API's tokens carry an audience. Every
 * violation is collected and startup fails with the whole list (the storage encryption is
 * checked by the storage module). Profile {@code local} only warns where a setting leaves
 * a door open that the admin API could walk through. Extensions add their own checks
 * ({@link ProfileCheck}); their problems join the list, tagged with the check's id.
 */
@ApplicationScoped
public class ProfileChecks {

    private static final Logger LOG = Logger.getLogger(ProfileChecks.class);

    @Inject
    McpServerConfig config;
    @Inject
    CallerAuth callers;
    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    ExtensionRegistry extensions;

    void onStart(@Observes StartupEvent event) {
        Optional<String> audience = ConfigProvider.getConfig()
            .getOptionalValue("quarkus.oidc.token.audience", String.class)
            .filter(v -> !v.isBlank());
        Settings s = new Settings(config.profile(), callers.oidcEnabled(), audience.isPresent(),
                !systems.allowedHosts().unrestricted(), config.admin().enabled(), config.admin().issuer().isPresent(),
                config.admin().audience().filter(v -> !v.isBlank()).isPresent(), config.admin().allowNewSystems());
        List<ProfileCheck> checks = extensions.extensions(ProfileCheck.class);
        for (ProfileCheck c : checks) {
            LOG.infof("Profile check '%s' registered (%s)", c.id(), c.getClass().getName());
        }
        Findings findings = run(s, checks,
                id -> new ProfileCheckContext(config.profile(), callers.required(), config,
                        ProviderConfig.forExtension(id, config.spi()),
                        name -> ConfigProvider.getConfig().getOptionalValue(name, String.class)));
        if (!findings.problems().isEmpty()) {
            throw new IllegalStateException("Startup checks of profile " + config.profile().name().toLowerCase()
                    + " failed: " + String.join("; ", findings.problems()));
        }
        for (String w : findings.warnings()) {
            LOG.warn(w);
        }
        String host = ConfigProvider.getConfig().getOptionalValue("quarkus.http.host", String.class).orElse("");
        if (!callers.required() && !isLoopback(host)) {
            LOG.warnf("The MCP endpoint is anonymous and listens on %s: everyone who reaches this address administers"
                    + " Keycloak with the server's credentials. Bind to 127.0.0.1 (quarkus.http.host), or require"
                    + " callers (kc-mcp.require-caller / kc-mcp.profile=shared).",
                    host.isEmpty() ? "all interfaces" : host);
        }
        LOG.infof(
                "Profile %s: callers %s, confirm-fallback %s, explicit-target %s, outbound hosts %s,"
                        + " dynamic-private-hosts %s",
                config.profile().name().toLowerCase(), callers.required() ? "required" : "optional",
                config.effectiveConfirmFallback().name().toLowerCase(),
                config.effectiveExplicitTarget().name().toLowerCase(),
                s.hostsRestricted() ? systems.allowedHosts().patterns() : "unrestricted",
                config.effectiveDynamicPrivateHosts().name().toLowerCase());
    }

    /** Whether a listen address only reaches this machine. */
    static boolean isLoopback(String host) {
        return switch (host.trim().toLowerCase(Locale.ROOT)) {
            case "localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1" -> true;
            default -> host.trim().startsWith("127.");
        };
    }

    /** Problems (stop the start) and warnings (logged) of all checks. */
    public record Findings(List<String> problems, List<String> warnings) {
    }

    /**
     * The built-in checks, then the extensions' in order: problems and warnings of each
     * extension are tagged {@code [id]}. A check that throws is a problem in profile
     * {@code shared} and a warning in {@code local}.
     */
    public static Findings run(Settings s, List<ProfileCheck> checks, Function<String, ProfileCheckContext> contexts) {
        List<String> problems = new ArrayList<>(
                problems(s).stream().map(p -> "kc-mcp.profile=shared needs " + p).toList());
        List<String> warnings = new ArrayList<>(warnings(s));
        for (ProfileCheck c : checks) {
            ProfileCheckContext ctx = contexts.apply(c.id());
            try {
                for (String p : nonNull(c.problems(ctx))) {
                    problems.add("[" + c.id() + "] " + p);
                }
                for (String w : nonNull(c.warnings(ctx))) {
                    warnings.add("[" + c.id() + "] " + w);
                }
            }
            catch (RuntimeException e) {
                String msg = "[" + c.id() + "] the check failed: " + e;
                if (s.profile().shared()) {
                    problems.add(msg);
                }
                else {
                    warnings.add(msg);
                }
            }
        }
        return new Findings(List.copyOf(problems), List.copyOf(warnings));
    }

    private static List<String> nonNull(List<String> l) {
        return l == null ? List.of() : l.stream().filter(v -> v != null && !v.isBlank()).toList();
    }

    /** The settings the checks look at, so they can be run without a container. */
    public record Settings(Profile profile, boolean oidcEnabled, boolean callerAudience, boolean hostsRestricted,
            boolean adminEnabled, boolean adminIssuer, boolean adminAudience, boolean adminAllowsNewSystems) {
    }

    /** What {@code shared} refuses to start without; empty for {@code local}. */
    public static List<String> problems(Settings s) {
        List<String> problems = new ArrayList<>();
        if (!s.profile().shared()) {
            return problems;
        }
        if (!s.oidcEnabled()) {
            problems.add("authenticated callers: quarkus.oidc.tenant-enabled=true (env QUARKUS_OIDC_TENANT_ENABLED)"
                    + " with quarkus.oidc.auth-server-url pointing at the realm that issues the caller tokens");
        }
        if (!s.callerAudience()) {
            problems.add("an audience on the caller tokens: quarkus.oidc.token.audience (env"
                    + " QUARKUS_OIDC_TOKEN_AUDIENCE), so that tokens issued for other services are refused");
        }
        if (!s.hostsRestricted()) {
            problems.add("the Keycloak hosts the server may talk to: kc-mcp.allowed-hosts (env KC_MCP_ALLOWED_HOSTS),"
                    + " e.g. *.example.com,sso.internal:8443");
        }
        if (s.adminEnabled() && s.adminIssuer() && !s.adminAudience()) {
            problems.add("an audience on the admin API tokens: kc-mcp.admin.audience (env KC_MCP_ADMIN_AUDIENCE)");
        }
        return problems;
    }

    /** Doors left open in {@code local} that are worth a line in the log. */
    public static List<String> warnings(Settings s) {
        List<String> warnings = new ArrayList<>();
        if (s.profile().shared()) {
            return warnings;
        }
        if (s.adminEnabled() && s.adminAllowsNewSystems() && !s.hostsRestricted()) {
            warnings.add("The admin API registers new Keycloak systems and kc-mcp.allowed-hosts is unset: a registered"
                    + " URL may point anywhere the server can reach (set kc-mcp.allowed-hosts, or"
                    + " kc-mcp.admin.allow-new-systems=false)");
        }
        if (!s.oidcEnabled()) {
            warnings.add("Profile local: the MCP endpoint is anonymous and every call runs with the server's own"
                    + " credentials; for a server other people reach set kc-mcp.profile=shared");
        }
        return warnings;
    }
}
