package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemSource;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.server.guard.ErrorMapper;
import com.github.thomasdarimont.keycloak.mcp.server.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * The Keycloak systems: the static ones from {@link McpServerConfig} plus whatever the
 * registered {@link KeycloakSystemSource}s supply at runtime. Admin clients are created
 * lazily per name and cached; a system whose settings change at the source is
 * reconnected, one the source no longer knows is dropped. Static systems outside
 * {@code kc-mcp.allowed-hosts} abort the startup, dynamic ones are refused and logged.
 */
@ApplicationScoped
public class DefaultKeycloakSystems implements KeycloakSystems {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakSystems.class);

    private final Map<String, KeycloakSystem> staticSystems = new LinkedHashMap<>();
    private final List<KeycloakSystemSource> sources;
    private final Map<String, KeycloakAdmin> admins = new ConcurrentHashMap<>();
    private final String defaultName;
    private final HostAllowList allowedHosts;
    private final SigningKeys keys;

    @Inject
    public DefaultKeycloakSystems(McpServerConfig config, SigningKeys keys, Extensions extensions) {
        this(resolve(config), config.defaultSystem().orElse(null), keys,
                HostAllowList.of(config.allowedHosts().orElse(List.of())), sources(config, extensions));
    }

    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys) {
        this(systems, defaultSystem, keys, HostAllowList.ANY, List.of());
    }

    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts) {
        this(systems, defaultSystem, keys, allowedHosts, List.of());
    }

    /**
     * @param allowedHosts the hosts the server may talk to; a static system outside the
     * list aborts the startup
     * @param sources runtime sources of systems, in order
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemSource> sources) {
        this.keys = keys;
        this.allowedHosts = allowedHosts;
        this.sources = List.copyOf(sources);
        if (systems.isEmpty() && sources.isEmpty()) {
            throw new IllegalStateException("No Keycloak system configured");
        }
        for (KeycloakSystem s : systems) {
            if (!allowedHosts.permits(s.url())) {
                throw new IllegalStateException("Keycloak system '" + s.name() + "' at " + s.url()
                        + " is not covered by kc-mcp.allowed-hosts " + allowedHosts.patterns());
            }
            staticSystems.put(s.name(), s);
        }
        if (!allowedHosts.unrestricted()) {
            LOG.infof("Keycloak hosts restricted to %s", allowedHosts.patterns());
        }
        for (KeycloakSystemSource src : this.sources) {
            LOG.infof("Keycloak system source '%s' registered (%s)", src.id(), src.getClass().getName());
        }
        if (defaultSystem != null) {
            if (!staticSystems.containsKey(defaultSystem) && lookup(defaultSystem).isEmpty()) {
                throw new IllegalStateException(
                        "kc-mcp.default-system '" + defaultSystem + "' is not one of " + names());
            }
            this.defaultName = defaultSystem;
        }
        else if (staticSystems.size() == 1 && this.sources.isEmpty()) {
            this.defaultName = staticSystems.keySet().iterator().next();
        }
        else {
            this.defaultName = staticSystems.containsKey(KeycloakSystem.DEFAULT_NAME) ? KeycloakSystem.DEFAULT_NAME
                    : null;
        }
        ErrorMapper.register(KeycloakErrors::map);
    }

    public static List<KeycloakSystem> resolve(McpServerConfig config) {
        if (!config.staticSystems()) {
            return List.of();
        }
        if (config.systems().isEmpty()) {
            return List.of(KeycloakSystem.fromTopLevel(config));
        }
        return config.systems()
            .entrySet()
            .stream()
            .sorted(Map.Entry.comparingByKey())
            .map(e -> KeycloakSystem.resolve(e.getKey(), config, e.getValue()))
            .toList();
    }

    /**
     * The registered sources, minus the disabled, in order; none unless
     * {@code kc-mcp.dynamic-systems=true}.
     */
    static List<KeycloakSystemSource> sources(McpServerConfig config, Extensions extensions) {
        List<KeycloakSystemSource> found = new ArrayList<>();
        for (KeycloakSystemSource s : extensions.discover(KeycloakSystemSource.class)) {
            if (!config.dynamicSystems()) {
                LOG.infof("Keycloak system source '%s' found but not used: set kc-mcp.dynamic-systems=true to let"
                        + " sources add systems at runtime", s.id());
                continue;
            }
            if (ProviderConfig.forExtension(s.id(), config.spi()).getBoolean("enabled", true)) {
                found.add(s);
            }
            else {
                LOG.infof("Keycloak system source '%s' disabled by configuration", s.id());
            }
        }
        found.sort(Comparator.comparingInt(Extension::order).thenComparing(Extension::id));
        return found;
    }

    /**
     * System names, default first, then the static ones alphabetically, then the
     * sources'.
     */
    @Override
    public List<String> names() {
        List<String> statics = new ArrayList<>(staticSystems.keySet());
        Collections.sort(statics);
        Set<String> names = new LinkedHashSet<>(statics);
        for (KeycloakSystemSource src : sources) {
            try {
                names.addAll(src.names());
            }
            catch (RuntimeException e) {
                LOG.warnf("Keycloak system source '%s' failed to list its systems: %s", src.id(), e.toString());
            }
        }
        List<String> out = new ArrayList<>(names);
        if (defaultName != null && out.remove(defaultName)) {
            out.add(0, defaultName);
        }
        return List.copyOf(out);
    }

    @Override
    public boolean multiple() {
        return dynamic() || staticSystems.size() > 1;
    }

    @Override
    public boolean dynamic() {
        return !sources.isEmpty();
    }

    /**
     * Name of the system used when none is given; empty when several systems exist and
     * none is the default.
     */
    @Override
    public Optional<String> defaultName() {
        return Optional.ofNullable(defaultName);
    }

    @Override
    public Optional<KeycloakAdmin> find(String name) {
        KeycloakSystem system = staticSystems.get(name);
        if (system == null) {
            system = lookup(name).orElse(null);
        }
        if (system == null) {
            KeycloakAdmin gone = admins.remove(name);
            if (gone != null) {
                LOG.infof("Keycloak system '%s' is gone from its source, disconnected", name);
                gone.close();
            }
            return Optional.empty();
        }
        KeycloakAdmin cached = admins.get(name);
        if (cached != null && cached.system().equals(system)) {
            return Optional.of(cached);
        }
        if (!allowedHosts.permits(system.url())) {
            LOG.warnf("Keycloak system '%s' at %s is not covered by kc-mcp.allowed-hosts %s, refused", name,
                    system.url(), allowedHosts.patterns());
            return Optional.empty();
        }
        KeycloakAdmin created = new DefaultKeycloakAdmin(system, keys);
        KeycloakAdmin previous = admins.put(name, created);
        if (previous != null) {
            LOG.infof("Keycloak system '%s' changed at its source, reconnecting to %s", name, system.url());
            previous.close();
        }
        else if (!staticSystems.containsKey(name)) {
            LOG.infof("Keycloak system '%s' at %s registered from a source", name, system.url());
        }
        return Optional.of(created);
    }

    private Optional<KeycloakSystem> lookup(String name) {
        for (KeycloakSystemSource src : sources) {
            try {
                Optional<KeycloakSystem> found = src.find(name);
                if (found.isPresent()) {
                    return found;
                }
            }
            catch (RuntimeException e) {
                LOG.warnf("Keycloak system source '%s' failed for '%s': %s", src.id(), name, e.toString());
            }
        }
        return Optional.empty();
    }

    @Override
    public KeycloakAdmin get(String name) {
        return find(name).orElseThrow(() -> new IllegalArgumentException(
                "Unknown Keycloak system '" + name + "', expected one of " + names()));
    }

    /** The default system's admin client; throws when ambiguous. */
    @Override
    public KeycloakAdmin defaultAdmin() {
        if (defaultName == null) {
            throw new IllegalStateException("Several Keycloak systems and no kc-mcp.default-system");
        }
        return get(defaultName);
    }

    @Override
    public List<KeycloakAdmin> all() {
        return names().stream().map(this::find).flatMap(Optional::stream).toList();
    }

    public boolean usesPrivateKeyJwt() {
        return dynamic() || staticSystems.values().stream().anyMatch(s -> s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    @PreDestroy
    void close() {
        admins.values().forEach(KeycloakAdmin::close);
    }
}
