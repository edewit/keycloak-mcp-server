package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.runtime.OidcConfig;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * With caller authentication on ({@code quarkus.oidc.tenant-enabled=true}), a request to
 * a bound entry ({@link EntryRoutes}) is verified against the realm that entry stands for
 * instead of the default tenant: a realm entry {@code /mcp/s/<system>/<realm>} logs its
 * users in at that realm, a system entry at the system's auth realm. The tenant
 * {@code kc-mcp-<system>[-<realm>]} copies the default tenant's settings (audience,
 * resource metadata) and points {@code auth-server-url} at
 * {@code <system url>/realms/<realm>}. Entries that resolve to the default tenant's realm
 * keep using it.
 */
@ApplicationScoped
public class EntryTenantResolver implements TenantConfigResolver {

    private static final Logger LOG = Logger.getLogger(EntryTenantResolver.class);

    /** Quarkus serves the RFC 9728 metadata of a path under this prefix. */
    static final String RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";

    @Inject
    KeycloakSystems systems;
    @Inject
    OidcConfig oidcConfig;
    @ConfigProperty(name = "quarkus.mcp.server.root-path", defaultValue = "/mcp")
    String rootPath;
    @ConfigProperty(name = "quarkus.oidc.tenant-enabled", defaultValue = "false")
    boolean tenantEnabled;

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext context, OidcRequestContext<OidcTenantConfig> requestContext) {
        if (!tenantEnabled) {
            return Uni.createFrom().nullItem();
        }
        String path = context.request().path();
        if (path != null && path.startsWith(RESOURCE_METADATA_PATH)) {
            // the protected-resource metadata of an entry describes that entry's tenant
            path = path.substring(RESOURCE_METADATA_PATH.length());
        }
        Optional<EntryBinding> binding = EntryRoutes.parse(path, rootPath);
        if (binding.isEmpty()) {
            return Uni.createFrom().nullItem();
        }
        // a system repository may go to a database: off the event loop
        return requestContext.runBlocking(() -> tenantFor(binding.get()));
    }

    /**
     * The tenant of an entry, {@code null} for the default tenant or an unknown system.
     */
    OidcTenantConfig tenantFor(EntryBinding binding) {
        Optional<KeycloakAdmin> admin = systems.find(binding.system());
        if (admin.isEmpty()) {
            return null;
        }
        KeycloakSystem system = admin.get().system();
        // a realm entry logs its users in at that realm, a system entry at the system's
        // auth realm
        String realm = binding.realm() != null ? binding.realm() : system.authRealm();
        String authServerUrl = system.url() + "/realms/" + realm;
        io.quarkus.oidc.runtime.OidcTenantConfig defaults = OidcConfig.getDefaultTenant(oidcConfig);
        if (authServerUrl.equals(defaults.authServerUrl().orElse(null))) {
            return null;
        }
        LOG.debugf("Entry %s: callers log in at %s", binding.describe(), authServerUrl);
        String entryPath = EntryRoutes.root(rootPath) + "/" + EntryRoutes.SEGMENT + "/" + system.name()
                + (binding.realm() != null ? "/" + realm : "");
        return OidcTenantConfig.builder(defaults)
            .tenantId("kc-mcp-" + system.name() + (binding.realm() != null ? "-" + realm : ""))
            .authServerUrl(authServerUrl)
            // RFC 9728: the metadata of the entry names the entry itself and the
            // realm's public URL,
            // which is what the MCP client's browser must reach
            .resourceMetadata()
            .resource(entryPath)
            .authorizationServer(system.publicUrl() + "/realms/" + realm)
            .end()
            .build();
    }
}
