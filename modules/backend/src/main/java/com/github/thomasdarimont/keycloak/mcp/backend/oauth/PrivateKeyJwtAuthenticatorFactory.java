package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.ClientAssertionTokenManager;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.JwtSigner;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticator;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticatorFactory;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
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

    public static final ConfigProperty KEY_FILE = ConfigProperty.string("jwt-key-file")
        .withLabel("Key file")
        .withDescription("PEM file (PKCS#8) of the private key the client assertions are signed with.");
    public static final ConfigProperty KEYSTORE_FILE = ConfigProperty.string("jwt-keystore-file")
        .withLabel("Keystore file")
        .withDescription("Keystore holding the signing key, instead of jwt-key-file.");
    public static final ConfigProperty KEYSTORE_PASSWORD = ConfigProperty.string("jwt-keystore-password")
        .asConfidential()
        .withLabel("Keystore password");
    public static final ConfigProperty KEYSTORE_TYPE = ConfigProperty.string("jwt-keystore-type")
        .withDefault("PKCS12")
        .withLabel("Keystore type");
    public static final ConfigProperty KEY_ALIAS = ConfigProperty.string("jwt-key-alias").withLabel("Key alias");
    public static final ConfigProperty KEY_PASSWORD = ConfigProperty.string("jwt-key-password")
        .asConfidential()
        .withLabel("Key password");
    public static final ConfigProperty KEY_ID = ConfigProperty.string("jwt-key-id")
        .withLabel("Key id")
        .withDescription("kid header of the assertions.");
    public static final ConfigProperty ALGORITHM = ConfigProperty.string("jwt-algorithm")
        .withLabel("Algorithm")
        .withDescription("RS256, PS256/384/512 or ES256/384/512; by default from the key.");
    public static final ConfigProperty ASSERTION_AUDIENCE = ConfigProperty.string("jwt-assertion-audience")
        .withLabel("Assertion audience")
        .withDescription("aud of the assertions; the token endpoint by default.");
    public static final ConfigProperty ASSERTION_LIFESPAN = ConfigProperty.integer("jwt-assertion-lifespan")
        .withDefault("60")
        .withLabel("Assertion lifespan")
        .withDescription("Seconds an assertion is valid.");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec
        .of(KEY_FILE, KEYSTORE_FILE, KEYSTORE_PASSWORD, KEYSTORE_TYPE, KEY_ALIAS, KEY_PASSWORD, KEY_ID, ALGORITHM,
                ASSERTION_AUDIENCE, ASSERTION_LIFESPAN)
        .withHints(
                ConfigHint.group("Client assertion key", KEY_FILE.name(), KEYSTORE_FILE.name(),
                        KEYSTORE_PASSWORD.name(), KEYSTORE_TYPE.name(), KEY_ALIAS.name(), KEY_PASSWORD.name(),
                        KEY_ID.name(), ALGORITHM.name()),
                ConfigHint.group("Client assertion", ASSERTION_AUDIENCE.name(), ASSERTION_LIFESPAN.name()),
                ConfigHint.when(KEYSTORE_PASSWORD.name()).isSet(KEYSTORE_FILE.name()),
                ConfigHint.when(KEYSTORE_TYPE.name()).isSet(KEYSTORE_FILE.name()),
                ConfigHint.when(KEY_ALIAS.name()).isSet(KEYSTORE_FILE.name()),
                ConfigHint.when(KEY_PASSWORD.name()).isSet(KEYSTORE_FILE.name()));

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    /** One key source: a PEM file or a keystore; with both the PEM file is used. */
    @Override
    public List<ConfigProblem> validate(ProviderConfig config) {
        if (config.isSet(KEY_FILE) && config.isSet(KEYSTORE_FILE)) {
            return List.of(ConfigProblem.warning(
                    config.key(KEY_FILE.name()) + " and " + config.key(KEYSTORE_FILE.name())
                            + " are both set; the key file is used, the keystore ignored",
                    KEY_FILE.name(), KEYSTORE_FILE.name()));
        }
        return List.of();
    }

    @Override
    public ClientAuthenticator create(Context context) {
        ProviderConfig cfg = context.config();
        Function<JsonObject, String> signer;
        if (cfg.isSet(KEY_FILE) || cfg.isSet(KEYSTORE_FILE)) {
            JwtSigner fromFile = JwtSigner.fromConfig(new KeySettings(cfg));
            signer = fromFile::sign;
        }
        else {
            signer = context.systemSigner()
                .orElseThrow(() -> new IllegalStateException(context.settingPrefix() + "client-auth=" + ID + " needs "
                        + context.settingPrefix() + "jwt-key-file or jwt-keystore-file: there is no Keycloak"
                        + " system key to sign with here"));
        }
        String audience = Optional.ofNullable(cfg.readString(ASSERTION_AUDIENCE))
            .orElse(context.tokenEndpoint().toString());
        int lifespan = cfg.readInt(ASSERTION_LIFESPAN);
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
            return Optional.ofNullable(cfg.readString(KEY_FILE));
        }

        @Override
        public Optional<String> keystoreFile() {
            return Optional.ofNullable(cfg.readString(KEYSTORE_FILE));
        }

        @Override
        public Optional<String> keystorePassword() {
            return Optional.ofNullable(cfg.readString(KEYSTORE_PASSWORD));
        }

        @Override
        public String keystoreType() {
            return cfg.readString(KEYSTORE_TYPE);
        }

        @Override
        public Optional<String> keyAlias() {
            return Optional.ofNullable(cfg.readString(KEY_ALIAS));
        }

        @Override
        public Optional<String> keyPassword() {
            return Optional.ofNullable(cfg.readString(KEY_PASSWORD));
        }

        @Override
        public Optional<String> publicKeyFile() {
            return Optional.empty();
        }

        @Override
        public Optional<String> keyId() {
            return Optional.ofNullable(cfg.readString(KEY_ID));
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
            return Optional.ofNullable(cfg.readString(ALGORITHM)).orElse("");
        }

        @Override
        public int keySize() {
            return 2048;
        }

        @Override
        public int assertionLifespan() {
            return cfg.readInt(ASSERTION_LIFESPAN);
        }
    }
}
