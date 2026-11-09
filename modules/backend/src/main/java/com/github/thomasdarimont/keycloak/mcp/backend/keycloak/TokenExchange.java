package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.function.Supplier;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.vertx.core.json.JsonObject;

/**
 * RFC 8693 delegation at Keycloak's token endpoint (feature
 * {@code token-exchange-delegation}, 26.8 preview): the caller's access token, which
 * carries a {@code may_act} claim naming this server's client, and the client's own
 * service-account token become one delegated access token. Its {@code sub} is the caller,
 * its {@code act} claim this client, its roles the caller's within this client's scope;
 * it has no refresh token and dies with the caller's session. Keycloak's audit shows the
 * exchange ({@code TOKEN_EXCHANGE}) and every admin call made with the token as the
 * caller's.
 */
public class TokenExchange {

    private static final Logger LOG = Logger.getLogger(TokenExchange.class);
    static final String GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    /** The error the model gets when Keycloak refuses the exchange. */
    public static final String ERROR = "delegation_failed";

    private final Client client;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final Supplier<String> clientAssertion;
    private final Supplier<String> actorToken;

    /**
     * @param actorToken the client's own service-account token, fetched when the exchange
     * happens
     */
    public TokenExchange(Client client, KeycloakSystem system, SigningKeys keys, Supplier<String> actorToken) {
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS || system.clientAuth() == ClientAuth.NONE) {
            throw new IllegalStateException("delegation=exchange needs a confidential client with a service account "
                    + "(grant client_credentials with a client secret or a private_key_jwt key) as the actor; system '"
                    + system.name() + "' uses grant " + system.grantType().oauthValue() + " with client auth "
                    + system.clientAuth());
        }
        this.client = client;
        String base = system.url().endsWith("/") ? system.url().substring(0, system.url().length() - 1) : system.url();
        this.tokenEndpoint = base + "/realms/" + system.authRealm() + "/protocol/openid-connect/token";
        this.clientId = system.clientId()
            .filter(v -> !v.isBlank())
            .orElseThrow(() -> new IllegalStateException("Missing configuration 'kc-mcp.systems.<name>.client-id'"));
        this.actorToken = actorToken;
        if (system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT) {
            this.clientSecret = null;
            this.clientAssertion = () -> ClientAssertionTokenManager.clientAssertion(clientId,
                    system.assertionAudience(), keys.signerFor(system), keys.assertionLifespan());
        }
        else {
            this.clientSecret = system.clientSecret()
                .filter(v -> !v.isBlank())
                .orElseThrow(
                        () -> new IllegalStateException("Missing configuration 'kc-mcp.systems.<name>.client-secret'"));
            this.clientAssertion = null;
        }
    }

    public String clientId() {
        return clientId;
    }

    /**
     * The scope an MCP client must request so the login grants delegation to this client.
     */
    public String delegationScope() {
        return delegationScope(clientId);
    }

    public static String delegationScope(String clientId) {
        return "delegation:client:" + clientId;
    }

    /**
     * Exchanges the caller's token for the delegated one.
     *
     * @throws ToolException {@value #ERROR} when Keycloak refuses, with what the caller
     * or an administrator has to change
     */
    public String exchange(String subjectToken) {
        Form form = new Form().param("grant_type", GRANT)
            .param("client_id", clientId)
            .param("subject_token", subjectToken)
            .param("subject_token_type", ACCESS_TOKEN_TYPE)
            .param("actor_token", actorToken.get())
            .param("actor_token_type", ACCESS_TOKEN_TYPE)
            .param("requested_token_type", ACCESS_TOKEN_TYPE);
        if (clientSecret != null) {
            form.param("client_secret", clientSecret);
        }
        else {
            form.param("client_assertion_type", ASSERTION_TYPE).param("client_assertion", clientAssertion.get());
        }
        try (Response response = client.target(tokenEndpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
                LOG.debugf("Token exchange for client %s refused: HTTP %d %s", clientId, response.getStatus(), body);
                throw refused(clientId, response.getStatus(), body);
            }
            String token = new JsonObject(body).getString("access_token");
            if (token == null || token.isBlank()) {
                throw new ToolException(ERROR, "Keycloak answered the token exchange without an access token.");
            }
            return token;
        }
    }

    /**
     * Keycloak's refusal as an error the model can explain: what Keycloak said and what
     * has to change.
     */
    static ToolException refused(String clientId, int status, String body) {
        String error = "";
        String description = "";
        try {
            JsonObject json = new JsonObject(body);
            error = json.getString("error", "");
            description = json.getString("error_description", "");
        }
        catch (RuntimeException e) {
            description = body == null ? "" : body.replaceAll("\\s+", " ").trim();
        }
        String said = (error + " " + description).trim();
        String scope = delegationScope(clientId);
        String fix;
        if (description.contains("may_act")) {
            fix = "The caller's login did not grant delegation to this server: the MCP client must request the scope '"
                    + scope + "' and the caller must consent to it at login (Keycloak asks every session); a Keycloak "
                    + "administrator must have granted the client '" + clientId
                    + "' the 'delegate' permission on the users (Admin Permissions). Log in again once that is in place.";
        }
        else if (status == 403) {
            fix = "Keycloak does not let the client '" + clientId + "' exchange this token: the token must name the "
                    + "client in its audience (the scope '" + scope + "' does that) and the client needs "
                    + "'Standard Token Exchange' enabled.";
        }
        else if (status == 401 || "invalid_client".equals(error) || "unauthorized_client".equals(error)) {
            fix = "The server's own client credentials were refused or the client may not use token exchange; "
                    + "check kc-mcp.systems.<name>.client-id / .client-secret and 'Standard Token Exchange' on the client.";
        }
        else if ("unsupported_grant_type".equals(error)) {
            fix = "This Keycloak does not offer token exchange delegation: it needs version 26.8 or later started with "
                    + "--features=token-exchange-delegation,parameterized-scopes.";
        }
        else {
            fix = "Check the Keycloak server log for the TOKEN_EXCHANGE_ERROR event.";
        }
        return new ToolException(ERROR, "Keycloak refused to issue a delegated token for the caller (HTTP " + status
                + ": " + said + "). " + fix);
    }

    public void close() {
        client.close();
    }
}
