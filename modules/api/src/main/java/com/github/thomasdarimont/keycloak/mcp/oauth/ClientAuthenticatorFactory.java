package com.github.thomasdarimont.keycloak.mcp.oauth;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

/**
 * Makes {@link ClientAuthenticator}s for one {@code token_endpoint_auth_method}. Built
 * in: {@code client_secret_basic}, {@code client_secret_post} and
 * {@code private_key_jwt}; further methods ({@code tls_client_auth}, a vendor's own)
 * register through {@code META-INF/services}
 * ({@code @AutoService(ClientAuthenticatorFactory.class)}), from the class path or the
 * providers directory, or as a CDI bean. A component that fetches tokens (the AuthZEN
 * check, for one) names the method in its settings ({@code client-auth=private_key_jwt})
 * and hands the factory those settings.
 */
public interface ClientAuthenticatorFactory {

    /**
     * The method's name as configured, the {@code token_endpoint_auth_method} value where
     * there is one ({@code private_key_jwt}).
     */
    String id();

    /**
     * The settings the method reads from the settings of the component that fetches the
     * tokens ({@code client-secret}, {@code jwt-key-file}): that component adds them to
     * its own spec, so they are checked, masked and documented with its settings. Empty
     * by default: nothing declared.
     */
    default ConfigSpec configSpec() {
        return ConfigSpec.EMPTY;
    }

    /**
     * The method's rules between its settings, as {@code Extension#validate}: called by
     * the component that fetches tokens with this method, on its settings.
     */
    default List<ConfigProblem> validate(ProviderConfig config) {
        return List.of();
    }

    /**
     * @throws IllegalStateException when a setting the method needs is missing or wrong;
     * thrown at startup where the settings are known then
     */
    ClientAuthenticator create(Context context);

    /**
     * What an authenticator is made from.
     *
     * @param clientId the client
     * @param tokenEndpoint where the tokens come from (the default {@code aud} of client
     * assertions)
     * @param config the settings of the component that fetches the tokens, e.g.
     * {@code client-secret}, {@code jwt-key-file}
     * @param settingPrefix the prefix of those settings in the configuration, for error
     * messages ({@code kc-mcp.spi.authorization-engine.authzen.})
     * @param systemSigner signs JWT claims with the key the server holds for the Keycloak
     * system concerned (the one published in its JWKS); empty when there is none
     */
    record Context(String clientId, URI tokenEndpoint, ProviderConfig config, String settingPrefix,
            Optional<Function<JsonObject, String>> systemSigner) {

        public Context {
            systemSigner = systemSigner == null ? Optional.empty() : systemSigner;
        }

        /** A setting the method cannot do without. */
        public String require(String method, String key) {
            return config.get(key)
                .map(String::trim)
                .orElseThrow(() -> new IllegalStateException(
                        settingPrefix + "client-auth=" + method + " needs " + settingPrefix + key));
        }
    }
}
