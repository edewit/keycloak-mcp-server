package org.keycloak.mcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.mcp.catalog.ApiOperation;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolCall;
import org.keycloak.mcp.catalog.ToolResult;
import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.spi.ToolProviderContext;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;

/**
 * REALM: server info, realm configuration and realm updates (login options, tokens, SMTP, WebAuthn passwordless).
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
                        .api(ApiOperation.unspecified("get", "/admin/serverinfo", "ServerInfoAdminResource is not part of the published OpenAPI document"))
                        .build(),
                tool("keycloak_realm_get_config")
                        .title("Get realm configuration")
                        .description("Key realm settings: login options, tokens, flows, SMTP host, password policy.")
                        .category(Category.REALM).read().hot()
                        .synonyms("settings", "realm config", "registration enabled", "token lifespan", "smtp",
                                "password policy", "brute force", "ssl required", "default locale")
                        .handler(this::realmConfig)
                        .api(get(R))
                        .build(),
                tool("keycloak_realm_update")
                        .title("Update realm settings")
                        .description("Change realm settings (login options, tokens, events, orgs, SMTP, WebAuthn); read-merge-write.")
                        .category(Category.REALM).destructive().idempotent(true)
                        .synonyms("enable registration", "enable events", "enable organizations", "smtp", "mail server",
                                "passwordless", "webauthn policy", "token lifespan", "password policy", "brute force",
                                "remember me", "realm settings")
                        .schema(schema()
                                .string("displayName", "Display name")
                                .bool("enabled", "Realm enabled")
                                .bool("registrationAllowed", "Self registration")
                                .bool("registrationEmailAsUsername", "Email as username")
                                .bool("loginWithEmailAllowed", "Login with email")
                                .bool("duplicateEmailsAllowed", "Allow duplicate emails")
                                .bool("resetPasswordAllowed", "Forgot password link")
                                .bool("rememberMe", "Remember me")
                                .bool("verifyEmail", "Require email verification")
                                .bool("editUsernameAllowed", "Users may edit their username")
                                .bool("bruteForceProtected", "Brute force detection")
                                .bool("eventsEnabled", "Save login events")
                                .bool("adminEventsEnabled", "Save admin events")
                                .bool("organizationsEnabled", "Enable organizations")
                                .integer("accessTokenLifespan", "Access token lifespan in seconds").min(1)
                                .integer("ssoSessionIdleTimeout", "SSO session idle in seconds").min(1)
                                .integer("ssoSessionMaxLifespan", "SSO session max in seconds").min(1)
                                .string("passwordPolicy", "Policy string, e.g. length(12) and digits(1)")
                                .string("defaultLocale", "Default locale, e.g. en")
                                .stringMap("smtpServer", "SMTP settings: host, port, from, fromDisplayName, auth, user, "
                                        + "password, starttls, ssl, replyTo")
                                .anyMap("webAuthnPasswordlessPolicy", "Keys: rpEntityName, rpId, signatureAlgorithms "
                                        + "(list), userVerificationRequirement, requireResidentKey, "
                                        + "authenticatorAttachment, attestationConveyancePreference"))
                        .handler(this::realmUpdate)
                        .api(put(R).body("RealmRepresentation", "displayName", "enabled", "registrationAllowed", "registrationEmailAsUsername", "loginWithEmailAllowed", "duplicateEmailsAllowed", "resetPasswordAllowed", "rememberMe", "verifyEmail", "editUsernameAllowed", "bruteForceProtected", "eventsEnabled", "adminEventsEnabled", "organizationsEnabled", "accessTokenLifespan", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "passwordPolicy", "defaultLocale", "smtpServer", "webAuthnPolicyPasswordlessRpEntityName", "webAuthnPolicyPasswordlessRpId", "webAuthnPolicyPasswordlessSignatureAlgorithms", "webAuthnPolicyPasswordlessUserVerificationRequirement", "webAuthnPolicyPasswordlessRequireResidentKey", "webAuthnPolicyPasswordlessAuthenticatorAttachment", "webAuthnPolicyPasswordlessAttestationConveyancePreference", "webAuthnPolicyPasswordlessCreateTimeout", "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister", "webAuthnPolicyPasswordlessAcceptableAaguids", "webAuthnPolicyPasswordlessPasskeysEnabled"))
                        .build());
    }

    ToolResult realmUpdate(ToolCall call) {
        RealmRepresentation r = kc.realm(call.realm()).toRepresentation();
        List<String> changed = new ArrayList<>();
        if (call.has("displayName")) { r.setDisplayName(call.str("displayName")); changed.add("displayName"); }
        if (call.has("enabled")) { r.setEnabled(call.bool("enabled")); changed.add("enabled"); }
        if (call.has("registrationAllowed")) { r.setRegistrationAllowed(call.bool("registrationAllowed")); changed.add("registrationAllowed"); }
        if (call.has("registrationEmailAsUsername")) { r.setRegistrationEmailAsUsername(call.bool("registrationEmailAsUsername")); changed.add("registrationEmailAsUsername"); }
        if (call.has("loginWithEmailAllowed")) { r.setLoginWithEmailAllowed(call.bool("loginWithEmailAllowed")); changed.add("loginWithEmailAllowed"); }
        if (call.has("duplicateEmailsAllowed")) { r.setDuplicateEmailsAllowed(call.bool("duplicateEmailsAllowed")); changed.add("duplicateEmailsAllowed"); }
        if (call.has("resetPasswordAllowed")) { r.setResetPasswordAllowed(call.bool("resetPasswordAllowed")); changed.add("resetPasswordAllowed"); }
        if (call.has("rememberMe")) { r.setRememberMe(call.bool("rememberMe")); changed.add("rememberMe"); }
        if (call.has("verifyEmail")) { r.setVerifyEmail(call.bool("verifyEmail")); changed.add("verifyEmail"); }
        if (call.has("editUsernameAllowed")) { r.setEditUsernameAllowed(call.bool("editUsernameAllowed")); changed.add("editUsernameAllowed"); }
        if (call.has("bruteForceProtected")) { r.setBruteForceProtected(call.bool("bruteForceProtected")); changed.add("bruteForceProtected"); }
        if (call.has("eventsEnabled")) { r.setEventsEnabled(call.bool("eventsEnabled")); changed.add("eventsEnabled"); }
        if (call.has("adminEventsEnabled")) { r.setAdminEventsEnabled(call.bool("adminEventsEnabled")); changed.add("adminEventsEnabled"); }
        if (call.has("organizationsEnabled")) { r.setOrganizationsEnabled(call.bool("organizationsEnabled")); changed.add("organizationsEnabled"); }
        if (call.has("accessTokenLifespan")) { r.setAccessTokenLifespan(call.integer("accessTokenLifespan")); changed.add("accessTokenLifespan"); }
        if (call.has("ssoSessionIdleTimeout")) { r.setSsoSessionIdleTimeout(call.integer("ssoSessionIdleTimeout")); changed.add("ssoSessionIdleTimeout"); }
        if (call.has("ssoSessionMaxLifespan")) { r.setSsoSessionMaxLifespan(call.integer("ssoSessionMaxLifespan")); changed.add("ssoSessionMaxLifespan"); }
        if (call.has("passwordPolicy")) { r.setPasswordPolicy(call.str("passwordPolicy")); changed.add("passwordPolicy"); }
        if (call.has("defaultLocale")) { r.setDefaultLocale(call.str("defaultLocale")); changed.add("defaultLocale"); }
        if (call.has("smtpServer")) {
            Map<String, String> smtp = r.getSmtpServer() == null ? new LinkedHashMap<>() : new LinkedHashMap<>(r.getSmtpServer());
            smtp.putAll(call.stringMap("smtpServer"));
            r.setSmtpServer(smtp);
            changed.add("smtpServer");
        }
        if (call.has("webAuthnPasswordlessPolicy")) {
            applyWebAuthnPasswordless(r, call.args().get("webAuthnPasswordlessPolicy"));
            changed.add("webAuthnPasswordlessPolicy");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one setting.");
        }
        kc.realm(call.realm()).update(r);
        return ToolResult.done("Realm updated", "realm", r.getRealm(), "changed", changed);
    }

    @SuppressWarnings("unchecked")
    private static void applyWebAuthnPasswordless(RealmRepresentation r, Object policy) {
        Map<String, Object> p = (Map<String, Object>) policy;
        for (Map.Entry<String, Object> e : p.entrySet()) {
            Object v = e.getValue();
            String s = v == null ? null : String.valueOf(v);
            switch (e.getKey()) {
                case "rpEntityName" -> r.setWebAuthnPolicyPasswordlessRpEntityName(s);
                case "rpId" -> r.setWebAuthnPolicyPasswordlessRpId(s);
                case "signatureAlgorithms" -> r.setWebAuthnPolicyPasswordlessSignatureAlgorithms(toList(v));
                case "userVerificationRequirement" -> r.setWebAuthnPolicyPasswordlessUserVerificationRequirement(s);
                case "requireResidentKey" -> r.setWebAuthnPolicyPasswordlessRequireResidentKey(s);
                case "authenticatorAttachment" -> r.setWebAuthnPolicyPasswordlessAuthenticatorAttachment(s);
                case "attestationConveyancePreference" -> r.setWebAuthnPolicyPasswordlessAttestationConveyancePreference(s);
                case "createTimeout" -> r.setWebAuthnPolicyPasswordlessCreateTimeout(Integer.parseInt(s));
                case "avoidSameAuthenticatorRegister" -> r.setWebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister(Boolean.parseBoolean(s));
                case "acceptableAaguids" -> r.setWebAuthnPolicyPasswordlessAcceptableAaguids(toList(v));
                case "passkeysEnabled" -> r.setWebAuthnPolicyPasswordlessPasskeysEnabled(Boolean.parseBoolean(s));
                default -> throw new org.keycloak.mcp.guard.ToolException("invalid_arguments",
                        "Unknown webAuthnPasswordlessPolicy key '" + e.getKey() + "'");
            }
        }
    }

    private static List<String> toList(Object v) {
        if (v instanceof List<?> l) {
            return l.stream().map(String::valueOf).toList();
        }
        List<String> out = new ArrayList<>();
        for (String part : String.valueOf(v).split(",")) {
            if (!part.isBlank()) {
                out.add(part.trim());
            }
        }
        return out;
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
        Map<String, Object> passwordless = new LinkedHashMap<>();
        passwordless.put("rpEntityName", r.getWebAuthnPolicyPasswordlessRpEntityName());
        passwordless.put("rpId", r.getWebAuthnPolicyPasswordlessRpId());
        passwordless.put("signatureAlgorithms", r.getWebAuthnPolicyPasswordlessSignatureAlgorithms());
        passwordless.put("userVerificationRequirement", r.getWebAuthnPolicyPasswordlessUserVerificationRequirement());
        passwordless.put("requireResidentKey", r.getWebAuthnPolicyPasswordlessRequireResidentKey());
        passwordless.put("authenticatorAttachment", r.getWebAuthnPolicyPasswordlessAuthenticatorAttachment());
        passwordless.values().removeIf(v -> v == null);
        m.put("webAuthnPasswordlessPolicy", passwordless);
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
