package org.keycloak.mcp.config;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.mcp.exposure.ExposureMode;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;
import io.smallrye.config.WithDefault;

/**
 * Server configuration. Every property maps to an env variable with the {@code KC_MCP_} prefix,
 * e.g. {@code kc-mcp.grant-type} -> {@code KC_MCP_GRANT_TYPE}.
 */
@ConfigMapping(prefix = "kc-mcp")
public interface McpServerConfig {

    /** Keycloak base URL, e.g. {@code http://localhost:8080}. */
    @WithDefault("http://localhost:8080")
    String url();

    /** OAuth grant used to obtain the admin token: {@code client_credentials} (default) or {@code password}. */
    @WithDefault("client_credentials")
    @WithConverter(GrantType.Converter.class)
    GrantType grantType();

    /**
     * Client authentication at the token endpoint: {@code client_secret}, {@code private_key_jwt} or {@code none}.
     * When unset it is inferred: a configured secret means {@code client_secret}, a configured JWT key means
     * {@code private_key_jwt}, otherwise {@code none} (public client, password grant only).
     */
    @WithConverter(ClientAuth.Converter.class)
    Optional<ClientAuth> clientAuth();

    default ClientAuth effectiveClientAuth() {
        if (clientAuth().isPresent()) {
            return clientAuth().get();
        }
        if (clientSecret().filter(s -> !s.isBlank()).isPresent()) {
            return ClientAuth.CLIENT_SECRET;
        }
        if (jwt().keyFile().isPresent() || jwt().keystoreFile().isPresent()) {
            return ClientAuth.PRIVATE_KEY_JWT;
        }
        return ClientAuth.NONE;
    }

    /** Realm the admin client / service account lives in. */
    @WithDefault("master")
    String authRealm();

    /** Defaults to {@code admin-cli} for the password grant with a public client. */
    Optional<String> clientId();

    Optional<String> clientSecret();

    /** Admin user for the password grant. */
    Optional<String> username();

    Optional<String> password();

    /** Key settings for {@link ClientAuth#PRIVATE_KEY_JWT}. */
    Jwt jwt();

    /** If set, the {@code realm} tool argument becomes optional and defaults to this realm. */
    Optional<String> defaultRealm();

    /** Realms the server may touch. Empty = all realms. */
    Optional<List<String>> allowedRealms();

    /** Hide and refuse every WRITE / DESTRUCTIVE tool. */
    @WithDefault("false")
    boolean readOnly();

    /** Which tools show up in {@code tools/list}. */
    @WithDefault("hybrid")
    @WithConverter(ExposureMode.Converter.class)
    ExposureMode toolExposure();

    /** Tools exposed directly in hybrid / progressive mode. */
    @WithDefault("keycloak_user_search,keycloak_user_get,keycloak_realm_get_config,keycloak_server_info")
    List<String> hotTools();

    /** Default number of hits returned by {@code search_tools}. */
    @WithDefault("5")
    int searchLimitDefault();

    /** Upper bound for the {@code max} pagination argument of list tools. */
    @WithDefault("100")
    int resultMaxItems();

    /**
     * Per tool-provider settings: {@code kc-mcp.spi.<provider-id>.<key>=value}
     * (env {@code KC_MCP_SPI_<ID>_<KEY>}). {@code enabled=false} switches a provider off.
     */
    Map<String, Map<String, String>> spi();

    /** Elicitation / confirmation prompt timeout in seconds. */
    @WithDefault("120")
    int confirmTimeoutSeconds();

    interface Jwt {
        /** Path to a PEM file with the client's private key (PKCS#8, {@code BEGIN PRIVATE KEY}). */
        Optional<String> keyFile();

        /** Alternatively: a PKCS12/JKS keystore holding the private key. */
        Optional<String> keystoreFile();

        Optional<String> keystorePassword();

        @WithDefault("PKCS12")
        String keystoreType();

        Optional<String> keyAlias();

        /** Password of the key entry; defaults to the keystore password. */
        Optional<String> keyPassword();

        /** Optional {@code kid} header, must match the key configured on the Keycloak client. */
        Optional<String> keyId();

        /** RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384 or PS512. */
        @WithDefault("RS256")
        String algorithm();

        /** Lifetime of each client assertion in seconds. */
        @WithDefault("60")
        int assertionLifespan();
    }
}
