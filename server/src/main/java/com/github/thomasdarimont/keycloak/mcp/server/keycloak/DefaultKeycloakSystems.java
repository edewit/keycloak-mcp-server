package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.server.guard.ErrorMapper;

/**
 * The configured Keycloak systems resolved from {@link McpServerConfig}, each with its
 * lazily connected {@link DefaultKeycloakAdmin}.
 */
@ApplicationScoped
public class DefaultKeycloakSystems implements KeycloakSystems {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakSystems.class);

    private final Map<String, KeycloakAdmin> admins = new LinkedHashMap<>();
    private final String defaultName;

    @Inject
    public DefaultKeycloakSystems(McpServerConfig config, JwtKeyMaterial jwtKeys) {
        this(resolve(config), config.defaultSystem().orElse(null), jwtKeys,
                HostAllowList.of(config.allowedHosts().orElse(List.of())));
    }

    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, JwtKeyMaterial jwtKeys) {
        this(systems, defaultSystem, jwtKeys, HostAllowList.ANY);
    }

    /**
     * @param allowedHosts the hosts the server may talk to; a system outside the list
     * aborts the startup
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, JwtKeyMaterial jwtKeys,
            HostAllowList allowedHosts) {
        if (systems.isEmpty()) {
            throw new IllegalStateException("No Keycloak system configured");
        }
        for (KeycloakSystem s : systems) {
            if (!allowedHosts.permits(s.url())) {
                throw new IllegalStateException("Keycloak system '" + s.name() + "' at " + s.url()
                        + " is not covered by kc-mcp.allowed-hosts " + allowedHosts.patterns());
            }
        }
        if (!allowedHosts.unrestricted()) {
            LOG.infof("Keycloak hosts restricted to %s", allowedHosts.patterns());
        }
        for (KeycloakSystem s : systems) {
            admins.put(s.name(), new DefaultKeycloakAdmin(s, jwtKeys));
        }
        if (defaultSystem != null) {
            if (!admins.containsKey(defaultSystem)) {
                throw new IllegalStateException(
                        "kc-mcp.default-system '" + defaultSystem + "' is not one of " + admins.keySet());
            }
            this.defaultName = defaultSystem;
        }
        else if (admins.size() == 1) {
            this.defaultName = admins.keySet().iterator().next();
        }
        else {
            this.defaultName = admins.containsKey(KeycloakSystem.DEFAULT_NAME) ? KeycloakSystem.DEFAULT_NAME : null;
        }
        ErrorMapper.register(KeycloakErrors::map);
    }

    public static List<KeycloakSystem> resolve(McpServerConfig config) {
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

    /** System names, default first, then alphabetical. */
    @Override
    public List<String> names() {
        List<String> names = new java.util.ArrayList<>(admins.keySet());
        java.util.Collections.sort(names);
        if (defaultName != null && names.remove(defaultName)) {
            names.add(0, defaultName);
        }
        return List.copyOf(names);
    }

    @Override
    public boolean multiple() {
        return admins.size() > 1;
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
        return Optional.ofNullable(admins.get(name));
    }

    @Override
    public KeycloakAdmin get(String name) {
        KeycloakAdmin a = admins.get(name);
        if (a == null) {
            throw new IllegalArgumentException("Unknown Keycloak system '" + name + "', expected one of " + names());
        }
        return a;
    }

    /** The default system's admin client; throws when ambiguous. */
    @Override
    public KeycloakAdmin defaultAdmin() {
        if (defaultName == null) {
            throw new IllegalStateException("Several Keycloak systems and no kc-mcp.default-system");
        }
        return admins.get(defaultName);
    }

    @Override
    public List<KeycloakAdmin> all() {
        return names().stream().map(admins::get).toList();
    }

    public boolean usesPrivateKeyJwt() {
        return admins.values().stream().anyMatch(a -> a.system().clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    @PreDestroy
    void close() {
        admins.values().forEach(KeycloakAdmin::close);
    }
}
