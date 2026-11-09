package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * {@code kc-mcp.spi.confirmer.ciba-confirmer.*}: the OpenID Connect CIBA client the
 * server asks the OpenID provider to authenticate the caller with before a destructive
 * tool runs. Only the standard flow is used (discovery,
 * {@code backchannel_authentication_endpoint}, {@code login_hint},
 * {@code binding_message}, poll mode at the token endpoint), so any CIBA-capable provider
 * works; Keycloak is the one the tests run against.
 *
 * @param enabled off by default
 * @param issuer issuer URL of the CIBA client, or {@code caller} for the issuer of the
 * caller's token (the default; the auth realm when the token has no issuer)
 * @param tokenIssuer the {@code iss} the provider's tokens carry when it differs from the
 * URL the server reaches the provider at (a container reaching Keycloak as
 * {@code http://keycloak:8080} while the tokens say {@code http://localhost:8098}); the
 * approval's ID token is verified against it. Unset: the same as the issuer
 * @param clientId the confidential client registered for CIBA
 * @param clientSecret its secret
 * @param clientAuth {@code client_secret_basic} (default) or {@code client_secret_post}
 * @param scope requested scope, {@code openid} by default
 * @param acrValues optional {@code acr_values}, e.g. to demand a second factor on the
 * device
 * @param loginHint {@code username} (the caller's name) or the name of a token claim
 * ({@code email}, {@code sub}) the provider resolves the user by (Keycloak: the realm's
 * CIBA "authentication requested user hint")
 * @param bindingMessage whether to send one; providers limit its length and characters,
 * the server keeps to Keycloak's rule (50 characters, no spaces)
 * @param bindingMessagePrefix start of the binding message shown on the device, followed
 * by a hash of the operation
 * @param requestedExpiry whether to ask for {@code requested_expiry} = the timeout
 * @param timeoutSeconds how long to wait for the approval; capped by the provider's
 * {@code expires_in}
 * @param when {@code always}, or {@code without-elicitation} to let a client that can ask
 * the human itself do so
 * @param flow {@code two-step} (default): the tool answers {@code confirmation_required}
 * right after filing the request, with the number the device asks for, and the next call
 * with the same arguments collects the approval; {@code blocking}: the call waits for the
 * device (no number matching possible, the chat shows nothing while waiting)
 * @param numberMatching two-step only: a two-digit number travels to the device as the
 * additional request parameter {@code code} and is shown to the model; the device asks
 * the user for it, so a request the user did not trigger cannot be approved (as Entra
 * ID's number matching)
 * @param extraParameters send {@code requester} (the MCP client's name) and
 * {@code operation} as additional request parameters for the device to show; providers
 * ignore parameters they do not know (Keycloak forwards up to five)
 * @param connectTimeout connect timeout of the calls to the provider; {@code null} for
 * {@code kc-mcp.http.connect-timeout}
 * @param readTimeout read timeout of those calls; {@code null} for
 * {@code kc-mcp.http.read-timeout}
 * @param tlsConfigurationName named TLS configuration ({@code quarkus.tls.<name>.*}) for
 * the calls to the provider, e.g. a trust store for a private CA; {@code null} for the
 * JVM's default trust
 * @param pollWaitSeconds two-step only: how long the collecting call waits for the device
 * before answering "still waiting"
 */
public record CibaSettings(boolean enabled, String issuer, String tokenIssuer, String clientId, String clientSecret,
        ClientAuth clientAuth, String scope, String acrValues, String loginHint, boolean bindingMessage,
        String bindingMessagePrefix, boolean requestedExpiry, int timeoutSeconds, When when, Flow flow,
        boolean numberMatching, boolean extraParameters, int pollWaitSeconds, String tlsConfigurationName,
        Duration connectTimeout, Duration readTimeout) {

    public enum Flow {
        TWO_STEP, BLOCKING;

        static Flow parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT).replace('_', '-')) {
                case "two-step", "2-step", "async" -> TWO_STEP;
                case "blocking", "wait", "sync" -> BLOCKING;
                default -> throw new IllegalArgumentException(
                        "kc-mcp.spi.confirmer.ciba-confirmer.flow must be two-step or blocking, not '" + v + "'");
            };
        }
    }

    public enum ClientAuth {
        BASIC, POST;

        static ClientAuth parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT).replace('-', '_')) {
                case "basic", "client_secret_basic" -> BASIC;
                case "post", "client_secret_post" -> POST;
                default -> throw new IllegalArgumentException("kc-mcp.spi.confirmer.ciba-confirmer.client-auth must be"
                        + " client_secret_basic or client_secret_post, not '" + v + "'");
            };
        }
    }

    public static final String ID = "ciba-confirmer";

    public enum When {
        ALWAYS, WITHOUT_ELICITATION;

        static When parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT).replace('_', '-')) {
                case "always" -> ALWAYS;
                case "without-elicitation", "no-elicitation", "fallback" -> WITHOUT_ELICITATION;
                default ->
                    throw new IllegalArgumentException("kc-mcp.spi.confirmer.ciba-confirmer.when must be always or"
                            + " without-elicitation, not '" + v + "'");
            };
        }
    }

    public static CibaSettings from(McpServerConfig server) {
        return from(ProviderConfig.forExtension(Confirmer.SPI, ID, server.spi()), server.confirmTimeoutSeconds());
    }

    public static CibaSettings from(ProviderConfig config, int defaultTimeout) {
        boolean enabled = config.getBoolean("enabled", false);
        Optional<String> clientId = config.get("client-id").filter(v -> !v.isBlank());
        Optional<String> secret = config.get("client-secret").filter(v -> !v.isBlank());
        if (enabled && (clientId.isEmpty() || secret.isEmpty())) {
            throw new IllegalStateException("kc-mcp.spi.confirmer.ciba-confirmer.enabled=true needs"
                    + " kc-mcp.spi.confirmer.ciba-confirmer.client-id and client-secret (a confidential Keycloak client with"
                    + " the CIBA grant enabled)");
        }
        return new CibaSettings(enabled, config.get("issuer", "caller"),
                config.get("token-issuer").filter(v -> !v.isBlank()).orElse(null), clientId.orElse(null),
                secret.orElse(null), ClientAuth.parse(config.get("client-auth", "client_secret_basic")),
                config.get("scope", "openid"), config.get("acr-values").filter(v -> !v.isBlank()).orElse(null),
                config.get("login-hint", "username"), config.getBoolean("binding-message", true),
                config.get("binding-message-prefix", "kc-mcp"), config.getBoolean("requested-expiry", false),
                config.getInt("timeout-seconds", defaultTimeout), When.parse(config.get("when", "always")),
                Flow.parse(config.get("flow", "two-step")), config.getBoolean("number-matching", true),
                config.getBoolean("extra-parameters", true), config.getInt("poll-wait-seconds", 5),
                config.get("tls-configuration-name").filter(v -> !v.isBlank()).orElse(null),
                OutboundClients
                    .duration(config.get("connect-timeout"), "kc-mcp.spi.confirmer.ciba-confirmer.connect-timeout")
                    .orElse(null),
                OutboundClients.duration(config.get("read-timeout"), "kc-mcp.spi.confirmer.ciba-confirmer.read-timeout")
                    .orElse(null));
    }

    /** Whether the issuer comes from the caller's token. */
    public boolean issuerFromCaller() {
        return "caller".equalsIgnoreCase(issuer);
    }
}
