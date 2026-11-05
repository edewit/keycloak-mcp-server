package com.github.thomasdarimont.keycloak.mcp.server.spi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.spi.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ToolProviderContext;

/**
 * The {@link ToolProvider}s found by {@link Extensions}: applies
 * {@code kc-mcp.spi.<id>.enabled}, initialises them in order and collects their tools and
 * access checks.
 */
@ApplicationScoped
public class ProviderRegistry {

    private static final Logger LOG = Logger.getLogger(ProviderRegistry.class);

    private final KeycloakSystems systems;

    private final McpServerConfig serverConfig;

    private final List<ToolProvider> providers;
    private final List<ToolSpec> specs;
    private final List<AccessCheck> accessChecks;

    @Inject
    public ProviderRegistry(Extensions extensions, KeycloakSystems systems, McpServerConfig serverConfig) {
        this(extensions.discover(ToolProvider.class), systems, serverConfig);
    }

    public ProviderRegistry(List<ToolProvider> candidates, KeycloakSystems systems, McpServerConfig serverConfig) {
        this.systems = systems;
        this.serverConfig = serverConfig;
        Map<String, ToolProvider> byId = new LinkedHashMap<>();
        for (ToolProvider p : candidates) {
            ToolProvider existing = byId.get(p.id());
            if (existing != null) {
                throw new IllegalStateException("Two tool providers share the id '" + p.id() + "': "
                        + existing.getClass().getName() + " and " + p.getClass().getName());
            }
            byId.put(p.id(), p);
        }
        List<ToolProvider> active = new ArrayList<>();
        List<ToolSpec> all = new ArrayList<>();
        List<AccessCheck> checks = new ArrayList<>();
        List<ToolProvider> sorted = new ArrayList<>(byId.values());
        sorted.sort(Comparator.comparingInt(ToolProvider::order).thenComparing(ToolProvider::id));
        for (ToolProvider p : sorted) {
            ProviderConfig pc = new ProviderConfig(p.id(), serverConfig.spi().get(p.id()));
            if (!pc.getBoolean("enabled", true)) {
                LOG.infof("Tool provider '%s' disabled by configuration", p.id());
                continue;
            }
            ToolProviderContext ctx = new Context(systems, serverConfig, pc);
            p.init(ctx);
            List<ToolSpec> tools = p.tools(ctx);
            LOG.infof("Tool provider '%s' (%s): %d tools", p.id(), p.displayName(), tools.size());
            all.addAll(tools);
            checks.addAll(p.accessChecks(ctx));
            active.add(p);
        }
        this.providers = List.copyOf(active);
        this.specs = List.copyOf(all);
        this.accessChecks = List.copyOf(checks);
    }

    /**
     * A provider context for an id, e.g. for prompt providers
     * ({@code kc-mcp.spi.<id>.*}).
     */
    public ToolProviderContext context(String providerId) {
        return new Context(systems, serverConfig, new ProviderConfig(providerId, serverConfig.spi().get(providerId)));
    }

    public List<ToolProvider> providers() {
        return providers;
    }

    public List<ToolSpec> specs() {
        return specs;
    }

    /** Global access checks contributed by the providers. */
    public List<AccessCheck> accessChecks() {
        return accessChecks;
    }

    @PreDestroy
    void shutdown() {
        for (ToolProvider p : providers) {
            try {
                p.close();
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Tool provider '%s' failed to close", p.id());
            }
        }
    }

    private record Context(KeycloakSystems systems, McpServerConfig serverConfig,
            ProviderConfig config) implements ToolProviderContext {
        @Override
        public KeycloakAdmin keycloak() {
            return systems.defaultName().map(systems::get).orElseGet(() -> systems.all().get(0));
        }
    }
}
