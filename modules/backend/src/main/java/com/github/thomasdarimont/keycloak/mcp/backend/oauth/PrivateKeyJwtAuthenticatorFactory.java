package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.util.Optional;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.ClientAssertionTokenManager;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.JwtSigner;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticator;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticatorFactory;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.google.auto.service.AutoService;

import io.vertx.core.json.JsonObject;

/**
 * {@code private_key_jwt} (RFC 7523, OIDC Core 9): a fresh signed assertion with every
 * token request, {@code iss} and {@code sub} the client, {@code aud} the token endpoint
 * unless {@code jwt-assertion-audience} says otherwise (some servers want their issuer).
 * The key: {@code jwt-key-file} (PEM, PKCS#8) or {@code jwt-keystore-file} (with
 * {@code jwt-keystore-password}, {@code jwt-keystore-type}, {@code jwt-key-alias},
 * {@code jwt-key-password}), plus {@code jwt-algorithm} (by default from the key: RS256
 * for RSA, ES256/ES384/ES512 by the curve of an EC key; PS256/384/512 when set) and
 * {@code jwt-key-id}; without either, the key the server holds for the Keycloak system
 * concerned, the one its JWKS endpoint publishes, so the authorization server can
 * register that JWKS URL. {@code jwt-assertion-lifespan}: seconds, 60 by default.
 */
@AutoService(ClientAuthenticatorFactory.class)
public final class PrivateKeyJwtAuthenticatorFactory implements ClientAuthenticatorFactory {

    public static final String ID = "private_key_jwt";
    static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ClientAuthenticator create(Context context) {
        ProviderConfig cfg = context.config();
        Function<JsonObject, String> signer;
        if (cfg.get("jwt-key-file").isPresent() || cfg.get("jwt-keystore-file").isPresent()) {
            JwtSigner fromFile = JwtSigner.fromConfig(new KeySettings(cfg));
            signer = fromFile::sign;
        }
        else {
            signer = context.systemSigner()
                .orElseThrow(() -> new IllegalStateException(context.settingPrefix() + "client-auth=" + ID + " needs "
                        + context.settingPrefix() + "jwt-key-file or jwt-keystore-file: there is no Keycloak"
                        + " system key to sign with here"));
        }
        String audience = cfg.get("jwt-assertion-audience")
            .map(String::trim)
            .orElse(context.tokenEndpoint().toString());
        int lifespan = cfg.getInt("jwt-assertion-lifespan", 60);
        String clientId = context.clientId();
        return request -> request.param("client_id", clientId)
            .param("client_assertion_type", ASSERTION_TYPE)
            .param("client_assertion",
                    signer.apply(ClientAssertionTokenManager.clientAssertionClaims(clientId, audience, lifespan)));
    }

    /** The {@code jwt-*} settings in the shape the signer loads keys from. */
    private record KeySettings(ProviderConfig cfg) implements McpServerConfig.Jwt {
        @Override
        public Optional<String> keyFile() {
            return cfg.get("jwt-key-file");
        }

        @Override
        public Optional<String> keystoreFile() {
            return cfg.get("jwt-keystore-file");
        }

        @Override
        public Optional<String> keystorePassword() {
            return cfg.get("jwt-keystore-password");
        }

        @Override
        public String keystoreType() {
            return cfg.get("jwt-keystore-type", "PKCS12");
        }

        @Override
        public Optional<String> keyAlias() {
            return cfg.get("jwt-key-alias");
        }

        @Override
        public Optional<String> keyPassword() {
            return cfg.get("jwt-key-password");
        }

        @Override
        public Optional<String> publicKeyFile() {
            return Optional.empty();
        }

        @Override
        public Optional<String> keyId() {
            return cfg.get("jwt-key-id");
        }

        @Override
        public boolean jwksEnabled() {
            return false;
        }

        @Override
        public String jwksPath() {
            return "";
        }

        @Override
        public String algorithm() {
            // blank: derived from the key (RS256, or ES256/384/512 by the EC curve)
            return cfg.get("jwt-algorithm", "");
        }

        @Override
        public int keySize() {
            return 2048;
        }

        @Override
        public int assertionLifespan() {
            return cfg.getInt("jwt-assertion-lifespan", 60);
        }
    }
}
