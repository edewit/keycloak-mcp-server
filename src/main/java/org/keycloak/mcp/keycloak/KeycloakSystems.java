package org.keycloak.mcp.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.config.ClientAuth;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.guard.ErrorMapper;

/**
 * All configured Keycloak systems and their (lazily connected) admin clients.
 */
@ApplicationScoped
public class KeycloakSystems {

    private final Map<String, KeycloakAdmin> admins = new LinkedHashMap<>();
    private final String defaultName;

    @Inject
    public KeycloakSystems(McpServerConfig config, JwtKeyMaterial jwtKeys) {
        this(resolve(config), config.defaultSystem().orElse(null), jwtKeys);
    }

    public KeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, JwtKeyMaterial jwtKeys) {
        if (systems.isEmpty()) {
            throw new IllegalStateException("No Keycloak system configured");
        }
        for (KeycloakSystem s : systems) {
            admins.put(s.name(), new KeycloakAdmin(s, jwtKeys));
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

    static List<KeycloakSystem> resolve(McpServerConfig config) {
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
    public List<String> names() {
        List<String> names = new java.util.ArrayList<>(admins.keySet());
        java.util.Collections.sort(names);
        if (defaultName != null && names.remove(defaultName)) {
            names.add(0, defaultName);
        }
        return List.copyOf(names);
    }

    public boolean multiple() {
        return admins.size() > 1;
    }

    /**
     * Name of the system used when none is given; empty when several systems exist and
     * none is the default.
     */
    public Optional<String> defaultName() {
        return Optional.ofNullable(defaultName);
    }

    public Optional<KeycloakAdmin> find(String name) {
        return Optional.ofNullable(admins.get(name));
    }

    public KeycloakAdmin get(String name) {
        KeycloakAdmin a = admins.get(name);
        if (a == null) {
            throw new IllegalArgumentException("Unknown Keycloak system '" + name + "', expected one of " + names());
        }
        return a;
    }

    /** The default system's admin client; throws when ambiguous. */
    public KeycloakAdmin defaultAdmin() {
        if (defaultName == null) {
            throw new IllegalStateException("Several Keycloak systems and no kc-mcp.default-system");
        }
        return admins.get(defaultName);
    }

    public List<KeycloakAdmin> all() {
        return List.copyOf(admins.values());
    }

    public boolean usesPrivateKeyJwt() {
        return admins.values().stream().anyMatch(a -> a.system().clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    @PreDestroy
    void close() {
        admins.values().forEach(KeycloakAdmin::close);
    }
}
