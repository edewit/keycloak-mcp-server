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

import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessTokenSource;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

/**
 * Caches the {@link GrantedRoles} of the server's token per Keycloak system.
 * {@link #peek} never blocks (for the tool filter); {@link #get} fetches a token on first
 * use and refreshes every few minutes (for handlers, which run on virtual threads).
 * Failures leave the roles {@link GrantedRoles#UNKNOWN}, which disables filtering.
 */
@ApplicationScoped
public class RoleDiscovery {

    private static final Logger LOG = Logger.getLogger(RoleDiscovery.class);
    private static final Duration REFRESH = Duration.ofMinutes(5);

    private record Snapshot(GrantedRoles roles, Instant at) {
    }

    private final Function<String, AccessTokenSource> sources;
    private final List<String> systems;
    private final boolean enabled;
    private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();
    private final Map<String, Boolean> warned = new ConcurrentHashMap<>();

    @Inject
    public RoleDiscovery(KeycloakSystems systems, McpServerConfig config) {
        // in forward mode the caller's token decides per call; the server may not even
        // have credentials
        this(systems.names(), systems::get, config.roleFilter() && config.delegation() == DelegationMode.OFF);
    }

    /** Single system, mostly for tests. */
    public RoleDiscovery(AccessTokenSource tokens, boolean enabled) {
        this(List.of("default"), name -> tokens, enabled);
    }

    public RoleDiscovery(List<String> systems, Function<String, AccessTokenSource> sources, boolean enabled) {
        this.systems = List.copyOf(systems);
        this.sources = sources;
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    public List<String> systems() {
        return systems;
    }

    /** Last known roles of one system without touching the network. */
    public GrantedRoles peek(String system) {
        if (!enabled) {
            return GrantedRoles.UNKNOWN;
        }
        Snapshot s = snapshots.get(system);
        return s == null ? GrantedRoles.UNKNOWN : s.roles();
    }

    /** Roles of the single/default system (tests and single-system setups). */
    public GrantedRoles peek() {
        return peek(systems.get(0));
    }

    public GrantedRoles get() {
        return get(systems.get(0));
    }

    /**
     * Roles of one system, discovering or refreshing them if needed. May block briefly.
     */
    public GrantedRoles get(String system) {
        if (!enabled) {
            return GrantedRoles.UNKNOWN;
        }
        Snapshot s = snapshots.get(system);
        if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
            return s.roles();
        }
        ReentrantLock lock = locks.computeIfAbsent(system, k -> new ReentrantLock());
        lock.lock();
        try {
            s = snapshots.get(system);
            if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
                return s.roles();
            }
            AccessTokenSource tokens = sources.apply(system);
            GrantedRoles roles = GrantedRoles.fromToken(tokens.accessToken(), tokens.authRealm());
            if (!roles.known() && warned.putIfAbsent(system, Boolean.TRUE) == null) {
                LOG.warnf("[%s] the admin token carries no realm-management roles; role based tool filtering is off."
                        + " Check the 'roles' client scope and the service account roles.", system);
            }
            else if (roles.known() && (s == null || !roles.equals(s.roles()))) {
                LOG.infof("[%s] admin token roles: %s", system,
                        roles.superAdmin() ? "super admin (master)" : roles.byRealm());
            }
            snapshots.put(system, new Snapshot(roles, Instant.now()));
            return roles;
        }
        catch (RuntimeException e) {
            LOG.warnf("[%s] role discovery failed, tool filtering by role is off until it succeeds: %s", system,
                    e.toString());
            snapshots.put(system, new Snapshot(GrantedRoles.UNKNOWN, Instant.now().minus(REFRESH).plusSeconds(30)));
            return GrantedRoles.UNKNOWN;
        }
        finally {
            lock.unlock();
        }
    }

    /** Whether the roles are held in any system (non-blocking). */
    public boolean anySystemPeek(java.util.function.Predicate<GrantedRoles> test) {
        for (String s : systems) {
            if (test.test(peek(s))) {
                return true;
            }
        }
        return false;
    }

    /** Whether the roles are held in any system (may discover). */
    public boolean anySystem(java.util.function.Predicate<GrantedRoles> test) {
        for (String s : systems) {
            if (test.test(get(s))) {
                return true;
            }
        }
        return false;
    }

    public void invalidate() {
        snapshots.clear();
    }
}
