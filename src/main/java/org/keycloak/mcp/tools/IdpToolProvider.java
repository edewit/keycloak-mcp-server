package org.keycloak.mcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jakarta.ws.rs.NotFoundException;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.Views;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;

/**
 * IDP: identity provider brokers (social, OIDC, SAML) and their mappers.
 */
public class IdpToolProvider extends AbstractToolProvider {

    static final Set<String> SECRET_KEYS = Set.of("clientSecret", "client_secret", "privateKey", "encryptionKey");

    @Override
    public String id() {
        return "idp";
    }

    @Override
    public String displayName() {
        return "Identity providers";
    }

    @Override
    public String description() {
        return "Identity provider brokers (Google, GitHub, Microsoft, OIDC, SAML) and their mappers.";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_idp_list")
                        .title("List identity providers")
                        .description("Identity providers configured for brokered / social login.")
                        .category(Category.IDP).read()
                        .synonyms("sso", "social login", "google", "github", "microsoft", "saml", "oidc broker",
                                "federated login", "login with")
                        .schema(schema().string("search", "Filter by alias or display name").pagination())
                        .handler(this::list)
                        .roles("view-identity-providers")
                        .api(get(R + "/identity-provider/instances").query("search", "first", "max"))
                        .build(),
                tool("keycloak_idp_get")
                        .title("Get identity provider")
                        .description("Settings of one identity provider; secrets are masked.")
                        .category(Category.IDP).read()
                        .synonyms("broker config", "client id of idp", "issuer", "first login flow", "hide on login")
                        .schema(schema().string("alias", "Identity provider alias, e.g. google").required())
                        .handler(this::get)
                        .roles("view-identity-providers")
                        .api(get(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
                        .build(),
                tool("keycloak_idp_mappers_list")
                        .title("List identity provider mappers")
                        .description("Mappers of an identity provider (attribute, role, username imports).")
                        .category(Category.IDP).read()
                        .synonyms("attribute importer", "role mapper", "username template", "claim to attribute")
                        .schema(schema().string("alias", "Identity provider alias").required())
                        .handler(this::mappers)
                        .roles("view-identity-providers")
                        .api(get(R + "/identity-provider/instances/{alias}/mappers").path("alias", "alias"))
                        .build(),
                tool("keycloak_idp_create")
                        .title("Create identity provider")
                        .description("Add a broker: providerId plus provider config like clientId, clientSecret, URLs.")
                        .category(Category.IDP).write()
                        .synonyms("add google login", "add github", "configure saml", "connect oidc provider",
                                "corporate sso", "login with")
                        .schema(schema()
                                .string("alias", "Unique alias, e.g. google or corp-sso").required()
                                .string("providerId", "Provider type: oidc, keycloak-oidc, saml, google, github, "
                                        + "microsoft, facebook, gitlab, linkedin-openid-connect, apple, ...").required()
                                .string("displayName", "Button label on the login page")
                                .bool("enabled", "Enabled (default true)")
                                .bool("trustEmail", "Trust emails from this provider as verified")
                                .bool("hideOnLogin", "Hide the button (used only for domain routing)")
                                .string("firstBrokerLoginFlowAlias", "First login flow (default 'first broker login')")
                                .stringMap("config", "Provider config: clientId, clientSecret, authorizationUrl, tokenUrl, "
                                        + "issuer, defaultScope, entityId, singleSignOnServiceUrl, ..."))
                        .handler(this::create)
                        .roles("manage-identity-providers")
                        .api(post(R + "/identity-provider/instances").body("IdentityProviderRepresentation", "alias", "providerId", "displayName", "enabled", "trustEmail", "hideOnLogin", "firstBrokerLoginFlowAlias", "config"))
                        .build(),
                tool("keycloak_idp_delete")
                        .title("Delete identity provider")
                        .description("Remove an identity provider and its mappers; linked users keep their accounts.")
                        .category(Category.IDP).destructive()
                        .synonyms("remove sso", "remove google login", "unconfigure broker")
                        .schema(schema().string("alias", "Identity provider alias").required())
                        .handler(this::delete)
                        .roles("manage-identity-providers")
                        .api(delete(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
                        .build());
    }

    static Map<String, Object> view(IdentityProviderRepresentation idp) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", idp.getAlias());
        Views.put(m, "displayName", idp.getDisplayName());
        m.put("providerId", idp.getProviderId());
        m.put("enabled", idp.isEnabled());
        if (Boolean.TRUE.equals(idp.isHideOnLogin())) {
            m.put("hideOnLogin", true);
        }
        if (Boolean.TRUE.equals(idp.isLinkOnly())) {
            m.put("linkOnly", true);
        }
        return m;
    }

    private static IdentityProviderRepresentation find(ToolCall call, String alias) {
        try {
            return call.kc().realm(call.realm()).identityProviders().get(alias).toRepresentation();
        } catch (NotFoundException e) {
            throw ToolException.notFound("Identity provider", alias);
        }
    }

    ToolResult list(ToolCall call) {
        List<IdentityProviderRepresentation> idps = call.kc().realm(call.realm()).identityProviders()
                .find(call.str("search"), true, call.first(), call.max());
        return ToolResult.ok(Views.page(Views.list(idps, IdpToolProvider::view), call.max()));
    }

    ToolResult get(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        Map<String, Object> m = view(idp);
        m.put("trustEmail", Boolean.TRUE.equals(idp.isTrustEmail()));
        m.put("storeToken", Boolean.TRUE.equals(idp.isStoreToken()));
        Views.put(m, "firstBrokerLoginFlowAlias", idp.getFirstBrokerLoginFlowAlias());
        Views.put(m, "postBrokerLoginFlowAlias", idp.getPostBrokerLoginFlowAlias());
        Views.put(m, "organizationId", idp.getOrganizationId());
        if (idp.getConfig() != null) {
            Map<String, Object> config = new LinkedHashMap<>();
            idp.getConfig().forEach((k, v) -> config.put(k, SECRET_KEYS.contains(k) ? "****" : v));
            m.put("config", config);
        }
        return ToolResult.ok(m);
    }

    ToolResult mappers(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        List<IdentityProviderMapperRepresentation> mappers = call.kc().realm(call.realm()).identityProviders()
                .get(idp.getAlias()).getMappers();
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityProviderMapperRepresentation mp : mappers) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", mp.getId());
            v.put("name", mp.getName());
            v.put("type", mp.getIdentityProviderMapper());
            if (mp.getConfig() != null && !mp.getConfig().isEmpty()) {
                v.put("config", mp.getConfig());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("alias", idp.getAlias());
        return ToolResult.ok(page);
    }

    ToolResult create(ToolCall call) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(call.str("alias"));
        idp.setProviderId(call.str("providerId"));
        idp.setDisplayName(call.str("displayName"));
        idp.setEnabled(call.bool("enabled", true));
        idp.setTrustEmail(call.bool("trustEmail", false));
        idp.setHideOnLogin(call.bool("hideOnLogin", false));
        if (call.has("firstBrokerLoginFlowAlias")) {
            idp.setFirstBrokerLoginFlowAlias(call.str("firstBrokerLoginFlowAlias"));
        }
        Map<String, String> config = new LinkedHashMap<>();
        if (call.has("config")) {
            config.putAll(Objects.requireNonNull(call.stringMap("config")));
        }
        idp.setConfig(config);
        KeycloakAdmin.ok(call.kc().realm(call.realm()).identityProviders().create(idp));
        return ToolResult.done("Identity provider created", "alias", idp.getAlias(), "providerId", idp.getProviderId());
    }

    ToolResult delete(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        call.kc().realm(call.realm()).identityProviders().get(idp.getAlias()).remove();
        return ToolResult.done("Identity provider deleted", "alias", idp.getAlias());
    }
}
