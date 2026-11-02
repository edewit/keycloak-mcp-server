package org.keycloak.mcp.spi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.KeycloakSystems;

/**
 * Discovers {@link ToolProvider}s (ServiceLoader + CDI), applies {@code kc-mcp.spi.<id>.enabled}, initialises them
 * in order and collects their tools.
 */
@ApplicationScoped
public class ToolProviderRegistry {

    private static final Logger LOG = Logger.getLogger(ToolProviderRegistry.class);

    private final List<ToolProvider> providers;
    private final List<ToolSpec> specs;
    private final List<AccessCheck> accessChecks;

    @Inject
    public ToolProviderRegistry(Instance<ToolProvider> cdiProviders, KeycloakSystems systems, McpServerConfig serverConfig) {
        this(discover(cdiProviders), systems, serverConfig);
    }

    public ToolProviderRegistry(List<ToolProvider> candidates, KeycloakSystems systems, McpServerConfig serverConfig) {
        Map<String, ToolProvider> byId = new LinkedHashMap<>();
        for (ToolProvider p : candidates) {
            ToolProvider existing = byId.get(p.id());
            if (existing != null) {
                if (existing.getClass().equals(p.getClass())) {
                    continue; // same class seen via ServiceLoader and CDI
                }
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

    static List<ToolProvider> discover(Instance<ToolProvider> cdiProviders) {
        List<ToolProvider> found = new ArrayList<>();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = ToolProviderRegistry.class.getClassLoader();
        }
        for (ToolProvider p : ServiceLoader.load(ToolProvider.class, cl)) {
            found.add(p);
        }
        if (cdiProviders != null) {
            for (ToolProvider p : cdiProviders) {
                found.add(p);
            }
        }
        return found;
    }

    public List<ToolProvider> providers() {
        return providers;
    }

    public List<ToolSpec> specs() {
        return specs;
    }

    /** Global access checks contributed by providers. */
    public List<AccessCheck> accessChecks() {
        return accessChecks;
    }

    @PreDestroy
    void shutdown() {
        for (ToolProvider p : providers) {
            try {
                p.close();
            } catch (RuntimeException e) {
                LOG.warnf(e, "Tool provider '%s' failed to close", p.id());
            }
        }
    }

    private record Context(KeycloakSystems systems, McpServerConfig serverConfig, ProviderConfig config)
            implements ToolProviderContext {
        @Override
        public KeycloakAdmin keycloak() {
            return systems.defaultName().map(systems::get).orElseGet(() -> systems.all().get(0));
        }
    }
}
