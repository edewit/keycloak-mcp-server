package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.ErrorMapper;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CompositeKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * The Keycloak systems: a {@link CompositeKeycloakSystemRepository} of the static
 * configuration (an {@link InMemoryKeycloakSystemRepository} named {@code static-config})
 * and the registered {@link KeycloakSystemRepository}s, with an admin client created
 * lazily per name and cached. A system whose settings change at its repository is
 * reconnected, one the repository no longer knows is dropped. Static systems outside
 * {@code kc-mcp.allowed-hosts} abort the startup, others are refused and logged.
 */
@ApplicationScoped
public class DefaultKeycloakSystems implements KeycloakSystems {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakSystems.class);

    /** Id of the repository holding the systems of the static configuration. */
    public static final String STATIC_REPOSITORY = "static-config";

    /**
     * Default of {@code kc-mcp.static-systems-order}: the static configuration is asked
     * first.
     */
    public static final int STATIC_ORDER = -1000;

    private final InMemoryKeycloakSystemRepository staticSystems;
    private final CompositeKeycloakSystemRepository repository;
    private final boolean dynamic;
    private final Map<String, KeycloakAdmin> admins = new ConcurrentHashMap<>();
    private final String defaultName;
    private final HostAllowList allowedHosts;
    private final SigningKeys keys;

    @Inject
    public DefaultKeycloakSystems(McpServerConfig config, SigningKeys keys, Extensions extensions) {
        this(resolve(config), config.defaultSystem().orElse(null), keys,
                HostAllowList.of(config.allowedHosts().orElse(List.of())), repositories(config, extensions),
                config.staticSystemsOrder());
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
     * @param repositories further repositories; the composite orders them by
     * {@code order()}
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemRepository> repositories) {
        this(systems, defaultSystem, keys, allowedHosts, repositories, STATIC_ORDER);
    }

    /**
     * @param staticOrder where the static configuration ranks among the repositories
     * ({@code kc-mcp.static-systems-order})
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemRepository> repositories, int staticOrder) {
        this.keys = keys;
        this.allowedHosts = allowedHosts;
        this.dynamic = !repositories.isEmpty();
        if (systems.isEmpty() && repositories.isEmpty()) {
            throw new IllegalStateException("No Keycloak system configured");
        }
        for (KeycloakSystem s : systems) {
            if (!allowedHosts.permits(s.url())) {
                throw new IllegalStateException("Keycloak system '" + s.name() + "' at " + s.url()
                        + " is not covered by kc-mcp.allowed-hosts " + allowedHosts.patterns());
            }
        }
        this.staticSystems = new InMemoryKeycloakSystemRepository(STATIC_REPOSITORY, staticOrder, systems);
        List<KeycloakSystemRepository> all = new ArrayList<>();
        all.add(staticSystems);
        all.addAll(repositories);
        this.repository = new CompositeKeycloakSystemRepository(all,
                (r, e) -> LOG.warnf("Keycloak system repository '%s' failed: %s", r.id(), e.toString()));
        if (!allowedHosts.unrestricted()) {
            LOG.infof("Keycloak hosts restricted to %s", allowedHosts.patterns());
        }
        for (KeycloakSystemRepository r : repositories) {
            LOG.infof("Keycloak system repository '%s' registered (%s)", r.id(), r.getClass().getName());
        }
        if (defaultSystem != null) {
            if (repository.find(defaultSystem).isEmpty()) {
                throw new IllegalStateException(
                        "kc-mcp.default-system '" + defaultSystem + "' is not one of " + names());
            }
            this.defaultName = defaultSystem;
        }
        else if (systems.size() == 1 && !dynamic) {
            this.defaultName = systems.get(0).name();
        }
        else {
            this.defaultName = staticSystems.find(KeycloakSystem.DEFAULT_NAME).isPresent() ? KeycloakSystem.DEFAULT_NAME
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
     * The registered repositories, minus the disabled, in order; none unless
     * {@code kc-mcp.dynamic-systems=true}.
     */
    static List<KeycloakSystemRepository> repositories(McpServerConfig config, Extensions extensions) {
        List<KeycloakSystemRepository> found = new ArrayList<>();
        for (KeycloakSystemRepository r : extensions.discover(KeycloakSystemRepository.class)) {
            if (!config.dynamicSystems()) {
                LOG.infof("Keycloak system repository '%s' found but not used: set kc-mcp.dynamic-systems=true to"
                        + " let repositories add systems at runtime", r.id());
                continue;
            }
            if (ProviderConfig.forExtension(r.id(), config.spi()).getBoolean("enabled", true)) {
                found.add(r);
            }
            else {
                LOG.infof("Keycloak system repository '%s' disabled by configuration", r.id());
            }
        }
        return found;
    }

    /**
     * The aggregated repositories: the static configuration first, then the registered
     * ones.
     */
    public CompositeKeycloakSystemRepository repository() {
        return repository;
    }

    /** The repository systems are registered in at runtime, when one is registered. */
    public Optional<MutableKeycloakSystemRepository> mutableRepository() {
        return repository.repository(MutableKeycloakSystemRepository.class);
    }

    /** The repository that knows a system, empty when none does. */
    public Optional<KeycloakSystemRepository> repositoryOf(String name) {
        return repository.repositories().stream().filter(r -> r.find(name).isPresent()).findFirst();
    }

    /** The hosts the server may talk to. */
    public HostAllowList allowedHosts() {
        return allowedHosts;
    }

    /** Disconnects a system right away (a repository removed it) and drops its signer. */
    public void forget(String name) {
        KeycloakAdmin gone = admins.remove(name);
        if (gone != null) {
            gone.close();
        }
        if (keys != null) {
            keys.forget(name);
        }
    }

    /**
     * A system with its {@code vault:} secret references resolved against the
     * {@link KeyVault}; a reference the vault cannot resolve is logged and left empty, so
     * the connection fails with a clear credentials error.
     */
    KeycloakSystem resolveSecrets(KeycloakSystem system) {
        if (keys == null) {
            return system;
        }
        return system.withClientSecret(resolve(system, system.clientSecret(), "clientSecret"))
            .withPassword(resolve(system, system.password(), "password"));
    }

    private Optional<String> resolve(KeycloakSystem system, Optional<String> value, String field) {
        if (value.isEmpty() || !KeycloakSystem.isVaultRef(value.get())) {
            return value;
        }
        KeyVault vault = keys.vault();
        String name = KeycloakSystem.vaultRefName(value.get());
        Optional<String> secret = vault.findSecret(name);
        if (secret.isEmpty()) {
            LOG.warnf("[%s] %s refers to the secret '%s', which KeyVault '%s' does not have", system.name(), field,
                    name, vault.id());
        }
        return secret;
    }

    /** System names, default first, then in repository order. */
    @Override
    public List<String> names() {
        List<String> out = new ArrayList<>(repository.names());
        if (defaultName != null && out.remove(defaultName)) {
            out.add(0, defaultName);
        }
        return List.copyOf(out);
    }

    @Override
    public boolean multiple() {
        return dynamic || staticSystems.names().size() > 1;
    }

    @Override
    public boolean dynamic() {
        return dynamic;
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
        KeycloakSystem system = repository.find(name).map(this::resolveSecrets).orElse(null);
        if (system == null) {
            KeycloakAdmin gone = admins.remove(name);
            if (gone != null) {
                LOG.infof("Keycloak system '%s' is gone from its repository, disconnected", name);
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
            LOG.infof("Keycloak system '%s' changed at its repository, reconnecting to %s", name, system.url());
            previous.close();
        }
        else if (staticSystems.find(name).isEmpty()) {
            LOG.infof("Keycloak system '%s' at %s registered from a repository", name, system.url());
        }
        return Optional.of(created);
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
        return dynamic || staticSystems.all().stream().anyMatch(s -> s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    @PreDestroy
    void close() {
        admins.values().forEach(KeycloakAdmin::close);
    }
}
