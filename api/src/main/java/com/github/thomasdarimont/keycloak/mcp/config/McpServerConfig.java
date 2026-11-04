package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;
import io.smallrye.config.WithDefault;

/**
 * Server configuration. Every property maps to an env variable with the {@code KC_MCP_}
 * prefix, e.g. {@code kc-mcp.grant-type} -> {@code KC_MCP_GRANT_TYPE}.
 */
@ConfigMapping(prefix = "kc-mcp")
public interface McpServerConfig {

    /** Keycloak base URL, e.g. {@code http://localhost:8080}. */
    @WithDefault("http://localhost:8080")
    String url();

    /**
     * Named Keycloak systems: {@code kc-mcp.systems.<name>.url} etc. Each field falls
     * back to the top-level value. When empty, the top-level settings form a single
     * system called {@code default}. With several systems the tools gain a {@code system}
     * argument.
     */
    Map<String, SystemSettings> systems();

    /**
     * System used when the {@code system} argument is omitted; inferred when only one
     * system exists.
     */
    Optional<String> defaultSystem();

    /**
     * Optional prefix for every tool name, e.g. {@code prod_} ->
     * {@code prod_keycloak_user_search}.
     */
    Optional<String> toolPrefix();

    /**
     * OAuth grant used to obtain the admin token: {@code client_credentials} (default) or
     * {@code password}.
     */
    @WithDefault("client_credentials")
    @WithConverter(GrantType.Converter.class)
    GrantType grantType();

    /**
     * Client authentication at the token endpoint: {@code client_secret},
     * {@code private_key_jwt} or {@code none}. When unset it is inferred: a configured
     * secret means {@code client_secret}, a configured JWT key means
     * {@code private_key_jwt}, otherwise {@code none} (public client, password grant
     * only).
     */
    @WithConverter(ClientAuth.Converter.class)
    Optional<ClientAuth> clientAuth();

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

    /**
     * {@code off} (default): admin calls use the server's own credentials;
     * {@code forward}: the caller's access token is forwarded to the Admin API, so
     * Keycloak enforces the user's own roles. {@code forward} requires the MCP endpoint
     * to authenticate callers ({@code quarkus.oidc.tenant-enabled=true}) and makes the
     * server credentials optional.
     */
    @WithDefault("off")
    @WithConverter(DelegationMode.Converter.class)
    DelegationMode delegation();

    /**
     * Refuse unauthenticated MCP requests with a 401 challenge even when the server acts
     * with its own credentials (the caller then only matters for policies and the audit
     * log). Implied by {@code delegation=forward}.
     */
    @WithDefault("false")
    boolean requireCaller();

    /**
     * If set, the {@code realm} tool argument becomes optional and defaults to this
     * realm.
     */
    Optional<String> defaultRealm();

    /** Realms the server may touch. Empty = all realms. */
    Optional<List<String>> allowedRealms();

    /** Hide and refuse every WRITE / DESTRUCTIVE tool. */
    @WithDefault("false")
    boolean readOnly();

    /** Only these tools exist on this server (csv of tool names). Empty = all. */
    Optional<List<String>> allowedTools();

    /**
     * These tools never exist on this server (csv). Wins over {@link #allowedTools()}.
     */
    Optional<List<String>> deniedTools();

    /**
     * Only tools of these categories exist (csv, e.g. {@code users,groups}). Empty = all.
     */
    Optional<List<String>> allowedCategories();

    /**
     * Hide and refuse tools whose realm-management roles the server's own token does not
     * hold.
     */
    @WithDefault("true")
    boolean roleFilter();

    /**
     * Startup check that every allowed realm is reachable with the credentials: off, warn
     * or fail.
     */
    @WithDefault("warn")
    String startupCheck();

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
     * Per tool-provider settings: {@code kc-mcp.spi.<provider-id>.<key>=value} (env
     * {@code KC_MCP_SPI_<ID>_<KEY>}). {@code enabled=false} switches a provider off.
     */
    Map<String, Map<String, String>> spi();

    /** Elicitation / confirmation prompt timeout in seconds. */
    @WithDefault("120")
    int confirmTimeoutSeconds();

    interface SystemSettings {
        Optional<String> url();

        @WithConverter(GrantType.Converter.class)
        Optional<GrantType> grantType();

        @WithConverter(ClientAuth.Converter.class)
        Optional<ClientAuth> clientAuth();

        Optional<String> authRealm();

        Optional<String> clientId();

        Optional<String> clientSecret();

        Optional<String> username();

        Optional<String> password();

        Optional<String> defaultRealm();

        Optional<List<String>> allowedRealms();
    }

    interface Jwt {
        /**
         * Path to a PEM file with the client's private key (PKCS#8,
         * {@code BEGIN PRIVATE KEY}).
         */
        Optional<String> keyFile();

        /** Alternatively: a PKCS12/JKS keystore holding the private key. */
        Optional<String> keystoreFile();

        Optional<String> keystorePassword();

        @WithDefault("PKCS12")
        String keystoreType();

        Optional<String> keyAlias();

        /** Password of the key entry; defaults to the keystore password. */
        Optional<String> keyPassword();

        /**
         * Public key / certificate PEM to publish in the JWKS; derived from the private
         * key when unset.
         */
        Optional<String> publicKeyFile();

        /**
         * {@code kid} in the JWS header and the JWKS; defaults to the RFC 7638 thumbprint
         * of the public key.
         */
        Optional<String> keyId();

        /**
         * Serve the public key as a JWK Set so Keycloak can fetch it via the client's
         * "JWKS URL" setting.
         */
        @WithDefault("true")
        boolean jwksEnabled();

        /** HTTP path of the JWK Set. */
        @WithDefault("/.well-known/jwks.json")
        String jwksPath();

        /** RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384 or PS512. */
        @WithDefault("RS256")
        String algorithm();

        /** Lifetime of each client assertion in seconds. */
        @WithDefault("60")
        int assertionLifespan();
    }
}
