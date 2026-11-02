package org.keycloak.mcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;

/**
 * REALM: server info and realm configuration. (realm_update, SMTP and WebAuthn settings follow in phase 4.)
 */
public class RealmToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "realm";
    }

    @Override
    public String displayName() {
        return "Realm and server";
    }

    @Override
    public String description() {
        return "Realm configuration and Keycloak server information.";
    }

    @Override
    public int order() {
        return 90;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_server_info")
                        .title("Server info")
                        .description("Keycloak version, enabled features and available themes.")
                        .category(Category.REALM).read().global().hot()
                        .synonyms("version", "health", "which keycloak", "features", "about")
                        .handler(this::serverInfo)
                        .build(),
                tool("keycloak_realm_get_config")
                        .title("Get realm configuration")
                        .description("Key realm settings: login options, tokens, flows, SMTP host, password policy.")
                        .category(Category.REALM).read().hot()
                        .synonyms("settings", "realm config", "registration enabled", "token lifespan", "smtp",
                                "password policy", "brute force", "ssl required", "default locale")
                        .handler(this::realmConfig)
                        .build());
    }

    ToolResult serverInfo(ToolCall call) {
        ServerInfoRepresentation info = kc.client().serverInfo().getInfo();
        Map<String, Object> m = new LinkedHashMap<>();
        if (info.getSystemInfo() != null) {
            m.put("version", info.getSystemInfo().getVersion());
            m.put("serverTime", info.getSystemInfo().getServerTime());
            m.put("uptime", info.getSystemInfo().getUptime());
        }
        if (info.getFeatures() != null) {
            m.put("enabledFeatures", info.getFeatures().stream().filter(f -> f.isEnabled()).map(f -> f.getName())
                    .sorted().toList());
        }
        if (info.getThemes() != null) {
            Map<String, Object> themes = new LinkedHashMap<>();
            info.getThemes().forEach((type, list) -> themes.put(type, list.stream().map(t -> t.getName()).toList()));
            m.put("themes", themes);
        }
        return ToolResult.ok(m);
    }

    ToolResult realmConfig(ToolCall call) {
        RealmRepresentation r = kc.realm(call.realm()).toRepresentation();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("realm", r.getRealm());
        m.put("displayName", r.getDisplayName());
        m.put("enabled", r.isEnabled());
        m.put("sslRequired", r.getSslRequired());
        Map<String, Object> login = new LinkedHashMap<>();
        login.put("registrationAllowed", r.isRegistrationAllowed());
        login.put("registrationEmailAsUsername", r.isRegistrationEmailAsUsername());
        login.put("loginWithEmailAllowed", r.isLoginWithEmailAllowed());
        login.put("duplicateEmailsAllowed", r.isDuplicateEmailsAllowed());
        login.put("resetPasswordAllowed", r.isResetPasswordAllowed());
        login.put("rememberMe", r.isRememberMe());
        login.put("verifyEmail", r.isVerifyEmail());
        login.put("editUsernameAllowed", r.isEditUsernameAllowed());
        login.put("bruteForceProtected", r.isBruteForceProtected());
        m.put("login", login);
        Map<String, Object> tokens = new LinkedHashMap<>();
        tokens.put("accessTokenLifespan", r.getAccessTokenLifespan());
        tokens.put("ssoSessionIdleTimeout", r.getSsoSessionIdleTimeout());
        tokens.put("ssoSessionMaxLifespan", r.getSsoSessionMaxLifespan());
        tokens.put("offlineSessionIdleTimeout", r.getOfflineSessionIdleTimeout());
        tokens.put("accessCodeLifespanUserAction", r.getAccessCodeLifespanUserAction());
        tokens.put("actionTokenGeneratedByAdminLifespan", r.getActionTokenGeneratedByAdminLifespan());
        m.put("tokens", tokens);
        Map<String, Object> flows = new LinkedHashMap<>();
        flows.put("browserFlow", r.getBrowserFlow());
        flows.put("registrationFlow", r.getRegistrationFlow());
        flows.put("directGrantFlow", r.getDirectGrantFlow());
        flows.put("resetCredentialsFlow", r.getResetCredentialsFlow());
        flows.put("clientAuthenticationFlow", r.getClientAuthenticationFlow());
        flows.put("dockerAuthenticationFlow", r.getDockerAuthenticationFlow());
        flows.put("firstBrokerLoginFlow", r.getFirstBrokerLoginFlow());
        m.put("flows", flows);
        m.put("passwordPolicy", r.getPasswordPolicy());
        m.put("otpPolicyType", r.getOtpPolicyType());
        m.put("webAuthnPolicyPasswordlessRpId", r.getWebAuthnPolicyPasswordlessRpId());
        m.put("defaultLocale", r.getDefaultLocale());
        m.put("internationalizationEnabled", r.isInternationalizationEnabled());
        m.put("eventsEnabled", r.isEventsEnabled());
        m.put("adminEventsEnabled", r.isAdminEventsEnabled());
        m.put("organizationsEnabled", r.isOrganizationsEnabled());
        if (r.getSmtpServer() != null && !r.getSmtpServer().isEmpty()) {
            Map<String, Object> smtp = new LinkedHashMap<>(r.getSmtpServer());
            smtp.remove("password");
            m.put("smtp", smtp);
        }
        m.values().removeIf(v -> v == null);
        return ToolResult.ok(m);
    }
}
