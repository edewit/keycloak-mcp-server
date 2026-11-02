package org.keycloak.mcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.mcp.catalog.ApiOperation;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.SynchronizationResultRepresentation;

/**
 * FEDERATION: user storage providers (LDAP, Active Directory, Kerberos) and sync.
 */
public class FederationToolProvider extends AbstractToolProvider {

    static final String PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider";
    static final Set<String> SECRET_KEYS = Set.of("bindCredential", "keyTab", "password");
    static final String PROVIDER_ID = "Provider id (UUID) or its display name, e.g. 'corp-ldap'";

    @Override
    public String id() {
        return "federation";
    }

    @Override
    public String displayName() {
        return "User federation";
    }

    @Override
    public String description() {
        return "LDAP / Active Directory / Kerberos user storage providers and synchronisation.";
    }

    @Override
    public int order() {
        return 70;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_federation_list")
                        .title("List user federation providers")
                        .description("User storage providers (LDAP, Active Directory, Kerberos) with key settings.")
                        .category(Category.FEDERATION).read()
                        .synonyms("ldap", "active directory", "ad", "kerberos", "user storage", "directory", "external users")
                        .handler(this::list)
                        .api(get(R + "/components").fixedQuery("parent", "type"))
                        .build(),
                tool("keycloak_federation_get")
                        .title("Get user federation provider")
                        .description("Full configuration of one user storage provider; credentials masked.")
                        .category(Category.FEDERATION).read()
                        .synonyms("ldap settings", "bind dn", "users dn", "edit mode", "connection url")
                        .schema(schema().string("id", PROVIDER_ID).required())
                        .handler(this::get)
                        .api(get(R + "/components").fixedQuery("parent", "type"))
                        .build(),
                tool("keycloak_federation_sync")
                        .title("Sync user federation provider")
                        .description("Import users from LDAP/AD now: all users (full) or only changed ones.")
                        .category(Category.FEDERATION).write()
                        .synonyms("import users", "ldap sync", "synchronize directory", "refresh users", "trigger sync")
                        .schema(schema()
                                .string("id", PROVIDER_ID).required()
                                .enumeration("mode", "full or changed (default changed)", "full", "changed").def("changed"))
                        .handler(this::sync)
                        .api(ApiOperation.unspecified("post", R + "/user-storage/{id}/sync", "UserStorageProviderResource is not part of the published OpenAPI document"))
                        .build());
    }

    private List<ComponentRepresentation> providers(String realm) {
        String realmId = kc.realm(realm).toRepresentation().getId();
        return kc.realm(realm).components().query(realmId, PROVIDER_TYPE);
    }

    private ComponentRepresentation find(String realm, String idOrName) {
        for (ComponentRepresentation c : providers(realm)) {
            if (idOrName.equals(c.getId()) || idOrName.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }
        throw ToolException.notFound("User federation provider", idOrName);
    }

    static String first(MultivaluedHashMap<String, String> config, String key) {
        return config == null ? null : config.getFirst(key);
    }

    static Map<String, Object> view(ComponentRepresentation c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("name", c.getName());
        m.put("providerId", c.getProviderId());
        MultivaluedHashMap<String, String> cfg = c.getConfig();
        Views.put(m, "enabled", first(cfg, "enabled"));
        Views.put(m, "priority", first(cfg, "priority"));
        Views.put(m, "editMode", first(cfg, "editMode"));
        Views.put(m, "importEnabled", first(cfg, "importEnabled"));
        Views.put(m, "connectionUrl", first(cfg, "connectionUrl"));
        Views.put(m, "usersDn", first(cfg, "usersDn"));
        Views.put(m, "vendor", first(cfg, "vendor"));
        Views.put(m, "fullSyncPeriod", first(cfg, "fullSyncPeriod"));
        Views.put(m, "changedSyncPeriod", first(cfg, "changedSyncPeriod"));
        return m;
    }

    ToolResult list(ToolCall call) {
        return ToolResult.ok(Views.page(Views.list(providers(call.realm()), FederationToolProvider::view),
                Integer.MAX_VALUE));
    }

    ToolResult get(ToolCall call) {
        ComponentRepresentation c = find(call.realm(), call.str("id"));
        Map<String, Object> m = view(c);
        Map<String, Object> config = new LinkedHashMap<>();
        if (c.getConfig() != null) {
            c.getConfig().forEach((k, v) -> config.put(k,
                    SECRET_KEYS.contains(k) ? "****" : v != null && v.size() == 1 ? v.get(0) : v));
        }
        m.put("config", config);
        return ToolResult.ok(m);
    }

    ToolResult sync(ToolCall call) {
        ComponentRepresentation c = find(call.realm(), call.str("id"));
        String action = "full".equals(call.str("mode", "changed")) ? "triggerFullSync" : "triggerChangedUsersSync";
        SynchronizationResultRepresentation r = kc.realm(call.realm()).userStorage().syncUsers(c.getId(), action);
        return ToolResult.done("Sync finished", "provider", c.getName(), "mode", call.str("mode", "changed"),
                "status", r.getStatus(), "added", r.getAdded(), "updated", r.getUpdated(), "removed", r.getRemoved(),
                "failed", r.getFailed(), "ignored", r.isIgnored());
    }
}
