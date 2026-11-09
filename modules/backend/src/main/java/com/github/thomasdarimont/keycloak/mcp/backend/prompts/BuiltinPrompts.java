package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.google.auto.service.AutoService;

/**
 * Recipes for recurring admin tasks. Each names the tools it needs; the registrar appends
 * their catalog entries, so even a small model can run the task without searching.
 */
@AutoService(PromptProvider.class)
public class BuiltinPrompts implements PromptProvider {

    @Override
    public String id() {
        return "built-in";
    }

    @Override
    public List<PromptSpec> prompts(ExtensionContext context) {
        // the shared default realm, when the systems have one; a system's own default
        // fills in at the call
        String realmHint = context.serverConfig()
            .systemDefaults()
            .defaultRealm()
            .map(r -> "Realm (default " + r + ")")
            .orElse("Realm the user lives in");
        return List.of(onboardUser(realmHint), loginTroubleshoot(realmHint));
    }

    static PromptSpec onboardUser(String realmHint) {
        return PromptSpec.builder("keycloak_onboard_user")
            .title("Onboard a new user")
            .description("Create a user, add them to groups and send the account setup email; verifies each step.")
            .argument("realm", realmHint)
            .required("username", "Username of the new account")
            .required("email", "Email address; the setup email goes there")
            .argument("firstName", "First name")
            .argument("lastName", "Last name")
            .argument("groups", "Groups to join, comma separated paths such as /staff/devs")
            .argument("actions", "Required actions for the setup email, comma separated", "UPDATE_PASSWORD")
            .tools("keycloak_user_search", "keycloak_user_create", "keycloak_group_member_add",
                    "keycloak_user_send_action_email", "keycloak_user_get", "keycloak_user_groups_list")
            .handler(BuiltinPrompts::renderOnboard)
            .build();
    }

    static String renderOnboard(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String names = (a.containsKey("firstName") ? ", first name " + a.get("firstName") : "")
                + (a.containsKey("lastName") ? ", last name " + a.get("lastName") : "");
        String groups = a.getOrDefault("groups", "").isBlank() ? "3. No groups were requested; skip group membership."
                : ("3. Add the user to the groups %s (one call per group, by path). "
                        + "A missing group is an error to report, not to create.")
                    .formatted(a.get("groups"));
        return """
                Onboard the user %s (%s)%s. Follow the steps in order and verify each.

                1. Make sure the account does not exist yet: search by username and by email. \
                If either exists, stop and report it; do not create a duplicate.
                2. Create the user: username, email%s, enabled. Do not set a password; the user chooses one \
                through the email.
                %s
                4. Send the account setup email with the required actions %s. Keycloak needs working SMTP \
                for this; report the error if sending fails.
                5. Verify: read the user back (enabled, email, required actions) and list their groups.
                6. Summarize for the admin: user id, groups, and that the setup email was sent to %s.

                If a step is refused as forbidden, call whoami and tell the admin which role is missing; do not retry.
                """.formatted(a.get("username"), a.get("email"), where, names, groups, a.get("actions"),
                a.get("email"));
    }

    static PromptSpec loginTroubleshoot(String realmHint) {
        return PromptSpec.builder("keycloak_login_troubleshoot")
            .title("Why can't a user log in?")
            .description("Read-only investigation of a user's login problems: account state, failed login events, "
                    + "realm and client settings; ends with the likely cause and a proposed fix.")
            .argument("realm", realmHint)
            .required("username", "Username, email or id of the affected user")
            .argument("client", "clientId of the application the user tries to log in to")
            .tools("keycloak_user_get", "keycloak_events_login", "keycloak_user_sessions_list",
                    "keycloak_realm_get_config", "keycloak_client_get", "keycloak_client_evaluate_scopes",
                    "keycloak_user_send_action_email")
            .handler(BuiltinPrompts::renderTroubleshoot)
            .build();
    }

    static String renderTroubleshoot(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String client = a.get("client");
        String target = client == null ? "" : " to the client " + client;
        String step5 = client == null
                ? "5. If the admin names an application later, read that client (enabled, flows, redirect URIs)."
                : ("5. Read the client %s: enabled, standard flow enabled, redirect URIs, then evaluate its scopes "
                        + "to see the roles and claims the user would get.")
                    .formatted(client);
        return """
                Find out why the user %s cannot log in%s%s. Investigate read-only; propose changes, but apply \
                none without the admin's go-ahead.

                1. Read the user: enabled? email verified? pending required actions? federated (LDAP) account? \
                A disabled account or a pending required action explains most cases.
                2. Read the user's recent login events and look at the error codes of the failures: \
                invalid_user_credentials (wrong password), user_disabled, user_temporarily_disabled \
                (brute force lockout), invalid_client_credentials, expired_code, and so on.
                3. Read the realm configuration: brute force protection and its lockout settings, \
                login with email, email verification, and which browser flow is bound.
                4. List the user's sessions: an active session means the credentials work and the problem is elsewhere.
                %s
                6. Report: the most likely cause, the evidence for it, and the fix. Typical fixes: enable the user, \
                clear or complete the required action, send a password reset email, wait out or lift the \
                brute force lockout, correct the client's redirect URI. Ask before changing anything.
                """.formatted(a.get("username"), where, target, step5);
    }

}
