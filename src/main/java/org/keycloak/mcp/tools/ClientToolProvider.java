package org.keycloak.mcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.Delegation;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

/**
 * CLIENTS and CLIENT_SCOPES.
 */
public class ClientToolProvider extends AbstractToolProvider {

    static final String SCOPE_TYPE_DESC = "default (always in the token) or optional (requested via scope param); default: default";

    @Override
    public String id() {
        return "clients";
    }

    @Override
    public String displayName() {
        return "Clients and client scopes";
    }

    @Override
    public String description() {
        return "OIDC/SAML clients, secrets, protocol mappers and client scope assignments.";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_client_list")
                        .title("List clients")
                        .description("Clients of the realm with id, clientId, protocol, enabled and public flags.")
                        .category(Category.CLIENTS).read()
                        .synonyms("applications", "apps", "oauth", "oidc", "saml", "service accounts", "which clients",
                                "relying party")
                        .schema(schema().string("search", "Filter by (partial) clientId").pagination())
                        .handler(this::list)
                        .roles("query-clients")
                        .api(get(R + "/clients").queryAs("clientId", "search").query("first", "max"))
                        .build(),
                tool("keycloak_client_get")
                        .title("Get client")
                        .description("Full client settings: flows, URIs, PKCE, auth type, scopes.")
                        .category(Category.CLIENTS).read()
                        .synonyms("redirect uris", "pkce", "flows enabled", "client details", "web origins")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::get)
                        .roles("view-clients")
                        .api(get(R + "/clients/{client-uuid}").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_get_secret")
                        .title("Get client secret")
                        .description("Client secret of a confidential client, masked unless reveal=true.")
                        .category(Category.CLIENTS).read()
                        .synonyms("credentials", "password of client", "show secret")
                        .schema(schema()
                                .string("clientId", CLIENT_ID).required()
                                .bool("reveal", "Return the plaintext secret (default false)"))
                        .handler(this::getSecret)
                        .delegation(Delegation.FORBIDDEN)
                        .roles("view-clients")
                        .api(get(R + "/clients/{client-uuid}/client-secret").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_regenerate_secret")
                        .title("Regenerate client secret")
                        .description("Rotate a confidential client's secret; the old one stops working at once.")
                        .category(Category.CLIENTS).destructive()
                        .synonyms("rotate", "new secret", "reset secret", "credentials")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::regenerateSecret)
                        .delegation(Delegation.FORBIDDEN)
                        .roles("manage-clients")
                        .api(post(R + "/clients/{client-uuid}/client-secret").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_create")
                        .title("Create client")
                        .description("Create an OIDC (or SAML) client; confidential by default, PKCE optional.")
                        .category(Category.CLIENTS).write()
                        .synonyms("register app", "new application", "spa", "mobile app", "service account", "oauth client")
                        .schema(clientFields(schema().string("clientId", "New clientId, e.g. my-app").required()
                                .enumeration("protocol", "Protocol (default openid-connect)", "openid-connect", "saml")))
                        .handler(this::create)
                        .roles("manage-clients")
                        .api(post(R + "/clients").body("ClientRepresentation", "clientId", "protocol", "name", "description", "enabled", "publicClient", "redirectUris", "webOrigins", "rootUrl", "baseUrl", "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "bearerOnly", "attributes"))
                        .build(),
                tool("keycloak_client_update")
                        .title("Update client")
                        .description("Change client settings; omitted fields stay, lists replace the old list.")
                        .category(Category.CLIENTS).write().idempotent(true)
                        .synonyms("edit app", "add redirect uri", "enable pkce", "disable client", "web origins")
                        .schema(clientFields(schema().string("clientId", CLIENT_ID).required()))
                        .handler(this::update)
                        .roles("manage-clients")
                        .api(put(R + "/clients/{client-uuid}").path("client-uuid", "clientId").body("ClientRepresentation", "name", "description", "enabled", "publicClient", "redirectUris", "webOrigins", "rootUrl", "baseUrl", "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "bearerOnly", "attributes"))
                        .build(),
                tool("keycloak_client_delete")
                        .title("Delete client")
                        .description("Permanently delete a client and its roles, mappers and service account.")
                        .category(Category.CLIENTS).destructive()
                        .synonyms("remove app", "unregister")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::delete)
                        .roles("manage-clients")
                        .api(delete(R + "/clients/{client-uuid}").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_mappers_list")
                        .title("List client protocol mappers")
                        .description("Protocol mappers defined directly on a client (claims added to its tokens).")
                        .category(Category.CLIENTS).read()
                        .synonyms("claims", "token mappers", "audience mapper", "attribute mapper")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::mappers)
                        .roles("view-clients")
                        .api(get(R + "/clients/{client-uuid}/protocol-mappers/models").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_scopes_list")
                        .title("List client scopes")
                        .description("Client scopes of the realm with protocol and realm-level default/optional flags.")
                        .category(Category.CLIENT_SCOPES).read()
                        .synonyms("scopes", "profile email roles", "available scopes", "offline_access")
                        .handler(this::scopesList)
                        .roles("view-clients")
                        .api(get(R + "/client-scopes"), get(R + "/default-default-client-scopes"), get(R + "/default-optional-client-scopes"))
                        .build(),
                tool("keycloak_client_default_scopes_get")
                        .title("Get a client's scopes")
                        .description("Default and optional client scopes assigned to one client.")
                        .category(Category.CLIENT_SCOPES).read()
                        .synonyms("assigned scopes", "scopes of app", "which scopes")
                        .schema(schema().string("clientId", CLIENT_ID).required())
                        .handler(this::clientScopes)
                        .roles("view-clients")
                        .api(get(R + "/clients/{client-uuid}/default-client-scopes").path("client-uuid", "clientId"), get(R + "/clients/{client-uuid}/optional-client-scopes").path("client-uuid", "clientId"))
                        .build(),
                tool("keycloak_client_scope_assign")
                        .title("Assign client scope")
                        .description("Attach a client scope to a client as default or optional scope.")
                        .category(Category.CLIENT_SCOPES).write().idempotent(true)
                        .synonyms("add scope", "attach scope", "enable scope for app")
                        .schema(schema()
                                .string("clientId", CLIENT_ID).required()
                                .string("scope", "Client scope name or id, e.g. email").required()
                                .enumeration("type", SCOPE_TYPE_DESC, "default", "optional").def("default"))
                        .handler(this::scopeAssign)
                        .roles("manage-clients")
                        .api(put(R + "/clients/{client-uuid}/default-client-scopes/{clientScopeId}").path("client-uuid", "clientId").path("clientScopeId", "scope"), put(R + "/clients/{client-uuid}/optional-client-scopes/{clientScopeId}").path("client-uuid", "clientId").path("clientScopeId", "scope"))
                        .build(),
                tool("keycloak_client_scope_unassign")
                        .title("Unassign client scope")
                        .description("Detach a client scope from a client.")
                        .category(Category.CLIENT_SCOPES).destructive()
                        .synonyms("remove scope", "detach scope", "disable scope for app")
                        .schema(schema()
                                .string("clientId", CLIENT_ID).required()
                                .string("scope", "Client scope name or id").required()
                                .enumeration("type", SCOPE_TYPE_DESC, "default", "optional").def("default"))
                        .handler(this::scopeUnassign)
                        .roles("manage-clients")
                        .api(delete(R + "/clients/{client-uuid}/default-client-scopes/{clientScopeId}").path("client-uuid", "clientId").path("clientScopeId", "scope"), delete(R + "/clients/{client-uuid}/optional-client-scopes/{clientScopeId}").path("client-uuid", "clientId").path("clientScopeId", "scope"))
                        .build());
    }

    private static org.keycloak.mcp.catalog.InputSchema.Builder clientFields(org.keycloak.mcp.catalog.InputSchema.Builder b) {
        return b.string("name", "Display name")
                .string("description", "Description")
                .bool("enabled", "Client enabled (default true)")
                .bool("publicClient", "Public client without secret, e.g. SPA or mobile (default false)")
                .stringArray("redirectUris", "Allowed redirect URIs, e.g. [\"https://app.example.com/*\"]")
                .stringArray("webOrigins", "Allowed CORS origins, \"+\" = all redirect URI origins")
                .string("rootUrl", "Root URL")
                .string("baseUrl", "Home/base URL")
                .bool("standardFlowEnabled", "Authorization code flow")
                .bool("implicitFlowEnabled", "Implicit flow (legacy)")
                .bool("directAccessGrantsEnabled", "Resource owner password grant")
                .bool("serviceAccountsEnabled", "Client credentials grant / service account")
                .bool("pkce", "Require PKCE with S256")
                .bool("bearerOnly", "Bearer-only (resource server, no login)");
    }

    // ---- handlers -----------------------------------------------------------------------------------------------

    ToolResult list(ToolCall call) {
        List<ClientRepresentation> clients = call.kc().realm(call.realm()).clients()
                .findAll(call.str("search"), true, call.has("search"), call.first(), call.max());
        return ToolResult.ok(Views.page(Views.list(clients, Views::client), call.max()));
    }

    ToolResult get(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        Map<String, Object> m = Views.client(c);
        Views.put(m, "description", c.getDescription());
        Views.put(m, "bearerOnly", c.isBearerOnly());
        Views.put(m, "standardFlowEnabled", c.isStandardFlowEnabled());
        Views.put(m, "implicitFlowEnabled", c.isImplicitFlowEnabled());
        Views.put(m, "directAccessGrantsEnabled", c.isDirectAccessGrantsEnabled());
        Views.put(m, "clientAuthenticatorType", c.getClientAuthenticatorType());
        Views.put(m, "rootUrl", c.getRootUrl());
        Views.put(m, "baseUrl", c.getBaseUrl());
        Views.put(m, "adminUrl", c.getAdminUrl());
        Views.put(m, "redirectUris", c.getRedirectUris());
        Views.put(m, "webOrigins", c.getWebOrigins());
        if (c.getAttributes() != null) {
            Views.put(m, "pkceMethod", c.getAttributes().get("pkce.code.challenge.method"));
            Views.put(m, "postLogoutRedirectUris", c.getAttributes().get("post.logout.redirect.uris"));
            Views.put(m, "accessTokenLifespan", c.getAttributes().get("access.token.lifespan"));
        }
        Views.put(m, "defaultClientScopes", c.getDefaultClientScopes());
        Views.put(m, "optionalClientScopes", c.getOptionalClientScopes());
        return ToolResult.ok(m);
    }

    ToolResult getSecret(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        if (Boolean.TRUE.equals(c.isPublicClient())) {
            throw new ToolException("public_client", "Client '" + c.getClientId() + "' is public and has no secret.");
        }
        CredentialRepresentation secret = call.kc().realm(call.realm()).clients().get(c.getId()).getSecret();
        String value = secret == null ? null : secret.getValue();
        return ToolResult.ok(Map.of("clientId", c.getClientId(),
                "secret", value == null ? "" : call.bool("reveal", false) ? value : mask(value),
                "revealed", call.bool("reveal", false)));
    }

    static String mask(String value) {
        if (value.length() <= 4) {
            return "****";
        }
        return "****" + value.substring(value.length() - 4);
    }

    ToolResult regenerateSecret(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        if (Boolean.TRUE.equals(c.isPublicClient())) {
            throw new ToolException("public_client", "Client '" + c.getClientId() + "' is public and has no secret.");
        }
        CredentialRepresentation secret = call.kc().realm(call.realm()).clients().get(c.getId()).generateNewSecret();
        return ToolResult.done("Secret regenerated", "clientId", c.getClientId(), "secret", secret.getValue());
    }

    ToolResult create(ToolCall call) {
        ClientRepresentation c = new ClientRepresentation();
        c.setClientId(call.str("clientId"));
        c.setProtocol(call.str("protocol", "openid-connect"));
        c.setEnabled(true);
        c.setPublicClient(false);
        c.setStandardFlowEnabled(true);
        c.setDirectAccessGrantsEnabled(false);
        apply(call, c);
        String id = KeycloakAdmin.created(call.kc().realm(call.realm()).clients().create(c));
        return ToolResult.done("Client created", "id", id, "clientId", c.getClientId(),
                "publicClient", c.isPublicClient());
    }

    ToolResult update(ToolCall call) {
        ClientResource res = call.kc().clientResource(call.realm(), call.str("clientId"));
        ClientRepresentation c = res.toRepresentation();
        List<String> changed = apply(call, c);
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one field besides clientId.");
        }
        res.update(c);
        return ToolResult.done("Client updated", "clientId", c.getClientId(), "changed", changed);
    }

    private static List<String> apply(ToolCall call, ClientRepresentation c) {
        List<String> changed = new ArrayList<>();
        if (call.has("name")) {
            c.setName(call.str("name"));
            changed.add("name");
        }
        if (call.has("description")) {
            c.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("enabled")) {
            c.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("publicClient")) {
            c.setPublicClient(call.bool("publicClient"));
            changed.add("publicClient");
        }
        if (call.has("redirectUris")) {
            c.setRedirectUris(call.strings("redirectUris"));
            changed.add("redirectUris");
        }
        if (call.has("webOrigins")) {
            c.setWebOrigins(call.strings("webOrigins"));
            changed.add("webOrigins");
        }
        if (call.has("rootUrl")) {
            c.setRootUrl(call.str("rootUrl"));
            changed.add("rootUrl");
        }
        if (call.has("baseUrl")) {
            c.setBaseUrl(call.str("baseUrl"));
            changed.add("baseUrl");
        }
        if (call.has("standardFlowEnabled")) {
            c.setStandardFlowEnabled(call.bool("standardFlowEnabled"));
            changed.add("standardFlowEnabled");
        }
        if (call.has("implicitFlowEnabled")) {
            c.setImplicitFlowEnabled(call.bool("implicitFlowEnabled"));
            changed.add("implicitFlowEnabled");
        }
        if (call.has("directAccessGrantsEnabled")) {
            c.setDirectAccessGrantsEnabled(call.bool("directAccessGrantsEnabled"));
            changed.add("directAccessGrantsEnabled");
        }
        if (call.has("serviceAccountsEnabled")) {
            c.setServiceAccountsEnabled(call.bool("serviceAccountsEnabled"));
            changed.add("serviceAccountsEnabled");
        }
        if (call.has("bearerOnly")) {
            c.setBearerOnly(call.bool("bearerOnly"));
            changed.add("bearerOnly");
        }
        if (call.has("pkce")) {
            Map<String, String> attrs = c.getAttributes() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(c.getAttributes());
            if (Boolean.TRUE.equals(call.bool("pkce"))) {
                attrs.put("pkce.code.challenge.method", "S256");
            } else {
                attrs.remove("pkce.code.challenge.method");
            }
            c.setAttributes(attrs);
            changed.add("pkce");
        }
        return changed;
    }

    ToolResult delete(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        call.kc().realm(call.realm()).clients().get(c.getId()).remove();
        return ToolResult.done("Client deleted", "clientId", c.getClientId(), "id", c.getId());
    }

    ToolResult mappers(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<ProtocolMapperRepresentation> mappers = call.kc().realm(call.realm()).clients().get(c.getId())
                .getProtocolMappers().getMappers();
        List<Map<String, Object>> items = new ArrayList<>();
        for (ProtocolMapperRepresentation m : mappers) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", m.getId());
            v.put("name", m.getName());
            v.put("type", m.getProtocolMapper());
            if (m.getConfig() != null && !m.getConfig().isEmpty()) {
                v.put("config", m.getConfig());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult scopesList(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        List<String> realmDefault = realm.getDefaultDefaultClientScopes().stream().map(ClientScopeRepresentation::getName)
                .toList();
        List<String> realmOptional = realm.getDefaultOptionalClientScopes().stream()
                .map(ClientScopeRepresentation::getName).toList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (ClientScopeRepresentation s : realm.clientScopes().findAll()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", s.getId());
            v.put("name", s.getName());
            Views.put(v, "protocol", s.getProtocol());
            Views.put(v, "description", s.getDescription());
            if (realmDefault.contains(s.getName())) {
                v.put("realmDefault", true);
            } else if (realmOptional.contains(s.getName())) {
                v.put("realmOptional", true);
            }
            items.add(v);
        }
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    ToolResult clientScopes(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        return ToolResult.ok(Map.of(
                "clientId", c.getClientId(),
                "defaultScopes", res.getDefaultClientScopes().stream().map(ClientScopeRepresentation::getName).sorted().toList(),
                "optionalScopes", res.getOptionalClientScopes().stream().map(ClientScopeRepresentation::getName).sorted().toList()));
    }

    private static ClientScopeRepresentation findScope(ToolCall call, String nameOrId) {
        for (ClientScopeRepresentation s : call.kc().realm(call.realm()).clientScopes().findAll()) {
            if (s.getName().equals(nameOrId) || s.getId().equals(nameOrId)) {
                return s;
            }
        }
        throw ToolException.notFound("Client scope", nameOrId);
    }

    ToolResult scopeAssign(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientScopeRepresentation s = findScope(call, call.str("scope"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        String type = call.str("type", "default");
        if ("optional".equals(type)) {
            res.addOptionalClientScope(s.getId());
        } else {
            res.addDefaultClientScope(s.getId());
        }
        return ToolResult.done("Scope assigned", "clientId", c.getClientId(), "scope", s.getName(), "type", type);
    }

    ToolResult scopeUnassign(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientScopeRepresentation s = findScope(call, call.str("scope"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        String type = call.str("type", "default");
        if ("optional".equals(type)) {
            res.removeOptionalClientScope(s.getId());
        } else {
            res.removeDefaultClientScope(s.getId());
        }
        return ToolResult.done("Scope unassigned", "clientId", c.getClientId(), "scope", s.getName(), "type", type);
    }
}
