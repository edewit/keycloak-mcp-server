package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

/**
 * Version and enabled features per Keycloak system, read from the admin server info with
 * the server's credentials and cached (like {@link RoleDiscovery}). A configured version
 * ({@code kc-mcp.version}, {@code kc-mcp.systems.<name>.version}) wins over the reported
 * one and stands in when the server info is not readable.
 */
@ApplicationScoped
public class CapabilityDiscovery {

    private static final Logger LOG = Logger.getLogger(CapabilityDiscovery.class);
    private static final Duration REFRESH = Duration.ofMinutes(10);
    private static final Duration RETRY = Duration.ofSeconds(30);

    /**
     * Oldest Keycloak the tool catalog is aligned with (OpenAPI document, Testcontainers
     * run).
     */
    public static final String BASELINE_VERSION = "26.8";

    private record Snapshot(ServerCapabilities caps, Instant at) {
    }

    private final List<String> systems;
    private final Function<String, ServerCapabilities> loader;
    private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();
    private final Map<String, Boolean> warned = new ConcurrentHashMap<>();

    @Inject
    public CapabilityDiscovery(KeycloakSystems systems) {
        this(systems.names(), name -> load(systems.get(name)));
    }

    public CapabilityDiscovery(List<String> systems, Function<String, ServerCapabilities> loader) {
        this.systems = List.copyOf(systems);
        this.loader = loader;
    }

    /** The same capabilities for every system, no network: tests and embedding. */
    public static CapabilityDiscovery fixed(ServerCapabilities caps) {
        return new CapabilityDiscovery(List.of("default"), name -> caps);
    }

    public List<String> systems() {
        return systems;
    }

    /** Last known capabilities of one system without touching the network. */
    public ServerCapabilities peek(String system) {
        Snapshot s = snapshots.get(system);
        return s == null ? ServerCapabilities.UNKNOWN : s.caps();
    }

    /** Capabilities of the single/default system. */
    public ServerCapabilities get() {
        return get(systems.get(0));
    }

    /**
     * Capabilities of one system, reading or refreshing them if needed. May block
     * briefly.
     */
    public ServerCapabilities get(String system) {
        Snapshot s = snapshots.get(system);
        if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
            return s.caps();
        }
        ReentrantLock lock = locks.computeIfAbsent(system, k -> new ReentrantLock());
        lock.lock();
        try {
            s = snapshots.get(system);
            if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
                return s.caps();
            }
            ServerCapabilities caps = loader.apply(system);
            if (!caps.versionKnown() && !caps.featuresKnown()) {
                if (warned.putIfAbsent(system, Boolean.TRUE) == null) {
                    LOG.warnf("[%s] Keycloak version and features unknown (server info not readable); capability"
                            + " checks are off. Set kc-mcp.version to enable the version checks.", system);
                }
                snapshots.put(system, new Snapshot(caps, Instant.now().minus(REFRESH).plus(RETRY)));
            }
            else {
                if (s == null || !caps.equals(s.caps())) {
                    LOG.infof("[%s] Keycloak %s%s", system, caps.versionKnown() ? caps.version() : "(version unknown)",
                            caps.featuresKnown() ? ", " + caps.features().size() + " features enabled" : "");
                    LOG.debugf("[%s] enabled features: %s", system, caps.features());
                }
                snapshots.put(system, new Snapshot(caps, Instant.now()));
            }
            return caps;
        }
        catch (RuntimeException e) {
            LOG.warnf("[%s] reading the server capabilities failed: %s", system, e.toString());
            snapshots.put(system, new Snapshot(ServerCapabilities.UNKNOWN, Instant.now().minus(REFRESH).plus(RETRY)));
            return ServerCapabilities.UNKNOWN;
        }
        finally {
            lock.unlock();
        }
    }

    public void invalidate() {
        snapshots.clear();
    }

    /**
     * Server info with the system's own credentials, the configured version applied on
     * top.
     */
    static ServerCapabilities load(KeycloakAdmin admin) {
        String configured = admin.system().version().orElse(null);
        ServerCapabilities caps;
        try {
            caps = ServerCapabilities.of(admin.client().serverInfo().getInfo());
        }
        catch (RuntimeException e) {
            if (admin.system().hasCredentials()) {
                LOG.debugf(e, "[%s] server info not readable", admin.name());
            }
            caps = ServerCapabilities.UNKNOWN;
        }
        if (configured != null) {
            if (caps.versionKnown() && ServerCapabilities.compareVersions(caps.version(), configured) != 0) {
                LOG.warnf("[%s] configured Keycloak version %s differs from the reported %s; using the configured one",
                        admin.name(), configured, caps.version());
            }
            caps = caps.withVersion(configured);
        }
        return caps;
    }
}
