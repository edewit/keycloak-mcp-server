package com.acme.keycloak.mcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.google.auto.service.AutoService;

/**
 * Extension point {@link KeycloakSystemRepository}: Keycloak systems from a tenant
 * registry, here a setting ({@code KC_MCP_SPI_ACME_TENANTS_SYSTEMS}) of the form
 * {@code alias=https://sso.tenant.example[|realm];...}. Each tenant registers the
 * confidential client {@code keycloak-mcp-server} with Signed JWT and the JWKS URL
 * {@code <server>/auth/keys/<alias>/jwks.json}; the server signs with its own key per
 * tenant, so no secret appears here. Active only with {@code kc-mcp.dynamic-systems=true}.
 */
@AutoService(KeycloakSystemRepository.class)
public class AcmeTenantRepository implements KeycloakSystemRepository {

    private final Map<String, KeycloakSystem> tenants;

    public AcmeTenantRepository() {
        this(ProviderConfig.forExtension("acme-tenants", Map.of()).get("systems", ""));
    }

    AcmeTenantRepository(String setting) {
        this.tenants = parse(setting);
    }

    @Override
    public String id() {
        return "acme-tenants";
    }

    @Override
    public List<String> names() {
        return List.copyOf(tenants.keySet());
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        return Optional.ofNullable(tenants.get(name));
    }

    /** {@code alias=url[|realm];alias=url} into systems; blank entries are skipped. */
    static Map<String, KeycloakSystem> parse(String setting) {
        Map<String, KeycloakSystem> out = new LinkedHashMap<>();
        for (String entry : setting.split(";")) {
            String[] aliasAndRest = entry.trim().split("=", 2);
            if (aliasAndRest.length != 2 || aliasAndRest[0].isBlank()) {
                continue;
            }
            String[] urlAndRealm = aliasAndRest[1].split("\\|", 2);
            String alias = aliasAndRest[0].trim();
            KeycloakSystem.Builder system = KeycloakSystem.builder(alias, urlAndRealm[0].trim())
                .clientId("keycloak-mcp-server")
                .displayName("ACME tenant " + alias);
            if (urlAndRealm.length == 2 && !urlAndRealm[1].isBlank()) {
                system.defaultRealm(urlAndRealm[1].trim()).allowedRealm(urlAndRealm[1].trim());
            }
            out.put(alias, system.build());
        }
        return out;
    }
}
