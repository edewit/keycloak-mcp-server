package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticator;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticatorFactory;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.google.auto.service.AutoService;

/**
 * The shared secret methods: {@code client_secret_basic} (HTTP basic, RFC 6749 2.3.1, id
 * and secret form-encoded first) and {@code client_secret_post} (both as form
 * parameters). Setting: {@code client-secret}.
 */
public final class ClientSecretAuthenticatorFactories {

    /** The client's secret. */
    public static final ConfigProperty CLIENT_SECRET = ConfigProperty.string("client-secret").asConfidential();

    static final ConfigSpec SPEC = ConfigSpec.of(CLIENT_SECRET);

    private ClientSecretAuthenticatorFactories() {
    }

    @AutoService(ClientAuthenticatorFactory.class)
    public static final class Basic implements ClientAuthenticatorFactory {

        public static final String ID = "client_secret_basic";

        @Override
        public String id() {
            return ID;
        }

        @Override
        public ConfigSpec configSpec() {
            return SPEC;
        }

        @Override
        public ClientAuthenticator create(Context context) {
            String secret = context.require(ID, CLIENT_SECRET.name());
            String credentials = Base64.getEncoder()
                .encodeToString((enc(context.clientId()) + ":" + enc(secret)).getBytes(StandardCharsets.UTF_8));
            return request -> request.header("Authorization", "Basic " + credentials);
        }
    }

    @AutoService(ClientAuthenticatorFactory.class)
    public static final class Post implements ClientAuthenticatorFactory {

        public static final String ID = "client_secret_post";

        @Override
        public String id() {
            return ID;
        }

        @Override
        public ConfigSpec configSpec() {
            return SPEC;
        }

        @Override
        public ClientAuthenticator create(Context context) {
            String secret = context.require(ID, CLIENT_SECRET.name());
            String clientId = context.clientId();
            return request -> request.param("client_id", clientId).param("client_secret", secret);
        }
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
