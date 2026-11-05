package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.CapabilityDiscovery;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.RoleDiscovery;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.quarkus.runtime.StartupEvent;

/**
 * Verifies at startup, per Keycloak system, that the credentials reach every allowed
 * realm and discovers the token's roles. {@code kc-mcp.startup-check=off|warn|fail}:
 * {@code warn} (default) runs in the background and logs, {@code fail} runs synchronously
 * and aborts startup on 401/403 or an unreachable realm.
 */
@ApplicationScoped
public class StartupChecks {

    private static final Logger LOG = Logger.getLogger(StartupChecks.class);

    @Inject
    McpServerConfig config;
    @Inject
    KeycloakSystems systems;
    @Inject
    RoleDiscovery roles;
    @Inject
    CapabilityDiscovery capabilities;
    @Inject
    ToolCatalog catalog;

    void onStart(@Observes StartupEvent event) {
        String mode = config.startupCheck().trim().toLowerCase(Locale.ROOT);
        switch (mode) {
            case "off" -> {
            }
            case "fail" -> {
                List<String> problems = run();
                if (!problems.isEmpty()) {
                    throw new IllegalStateException("Keycloak startup check failed: " + String.join("; ", problems));
                }
            }
            default -> Thread.ofVirtual().name("kc-mcp-startup-check").start(() -> {
                try {
                    run();
                }
                catch (RuntimeException e) {
                    LOG.warnf("Startup check skipped: %s", e.toString());
                }
            });
        }
    }

    /** Runs the checks for every system and returns the problems found (also logged). */
    public List<String> run() {
        List<String> problems = new ArrayList<>();
        for (KeycloakAdmin admin : systems.all()) {
            problems.addAll(run(admin));
        }
        return problems;
    }

    List<String> run(KeycloakAdmin admin) {
        String sys = admin.name();
        List<String> problems = new ArrayList<>();
        if (config.delegation() == DelegationMode.FORWARD && !admin.system().hasCredentials()) {
            LOG.infof("[%s] delegation=forward without server credentials: every admin call uses the caller's token,"
                    + " startup check skipped", sys);
            return problems;
        }
        GrantedRoles granted;
        try {
            granted = roles.get(sys);
        }
        catch (RuntimeException e) {
            problems.add("[" + sys + "] cannot obtain an admin token: " + root(e));
            LOG.errorf("[%s] Keycloak at %s: cannot obtain an admin token (%s)", sys, admin.system().url(), root(e));
            return problems;
        }
        List<String> realms = new ArrayList<>(admin.system().allowedRealms());
        admin.system().defaultRealm().ifPresent(r -> {
            if (!realms.contains(r)) {
                realms.add(r);
            }
        });
        for (String r : realms) {
            try {
                admin.realm(r).toRepresentation();
                LOG.infof("[%s] realm '%s' reachable%s", sys, r, granted.known() && !granted.superAdmin()
                        ? " with roles " + granted.byRealm().getOrDefault(r, Set.of()) : "");
            }
            catch (WebApplicationException e) {
                int status = e.getResponse().getStatus();
                String msg = "[" + sys + "] realm '" + r + "' answered HTTP " + status
                        + (status == 401 || status == 403 ? " (credentials lack access)" : "");
                problems.add(msg);
                LOG.error("Keycloak startup check: " + msg);
            }
            catch (ProcessingException e) {
                problems.add("[" + sys + "] realm '" + r + "' unreachable: " + root(e));
                LOG.errorf("Keycloak startup check: [%s] realm '%s' unreachable (%s)", sys, r, root(e));
            }
        }
        if (granted.known() && !granted.superAdmin()) {
            for (String r : realms) {
                if (!granted.reaches(r)) {
                    String msg = "[" + sys + "] token has no admin roles in realm '" + r + "' (has: " + granted.realms()
                            + ")";
                    problems.add(msg);
                    LOG.error("Keycloak startup check: " + msg);
                }
            }
        }
        problems.addAll(checkCapabilities(sys));
        return problems;
    }

    /** Version against the baseline, and which tools the server cannot serve. */
    List<String> checkCapabilities(String sys) {
        List<String> problems = new ArrayList<>();
        ServerCapabilities caps = capabilities.get(sys);
        if (caps.versionKnown() && !caps.atLeast(CapabilityDiscovery.BASELINE_VERSION)) {
            String msg = "[" + sys + "] Keycloak " + caps.version() + " is below the supported baseline "
                    + CapabilityDiscovery.BASELINE_VERSION + "; tools may fail or behave differently";
            problems.add(msg);
            LOG.error("Keycloak startup check: " + msg);
        }
        Map<String, List<String>> unavailable = new TreeMap<>();
        for (ToolSpec spec : catalog.all()) {
            AccessPolicy.unsupported(spec, caps)
                .ifPresent(why -> unavailable.computeIfAbsent(why, k -> new ArrayList<>()).add(spec.name()));
        }
        unavailable.forEach((why, tools) -> LOG.infof("[%s] %d tools unavailable: %s (%s)", sys, tools.size(), why,
                String.join(", ", tools)));
        return problems;
    }

    private static String root(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }
}
