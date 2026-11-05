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
     * For whom the explanation is worded when a tool cannot run on this server:
     * {@code admins} (configuration details and {@code howToFix}), {@code users} (plain:
     * not available here, an administrator can change it) or {@code auto} (by the
     * caller's roles in delegation mode, else admins). Unrelated to the OAuth audience.
     */
    @WithDefault("auto")
    @WithConverter(Explanations.Converter.class)
    Explanations explanations();

    /**
     * Keycloak version of the (default) system, e.g. {@code 26.8.1}, when the server info
     * endpoint is not readable or should be overridden. Tools that need a newer version
     * are refused with {@code unsupported}; unknown means unchecked.
     */
    Optional<String> version();

    /**
     * Issuer URL of the auth realm as Keycloak states it
     * ({@code https://sso.example.com/realms/master}), used as the audience of
     * {@code private_key_jwt} client assertions when {@code kc-mcp.url} is an internal
     * address that differs from Keycloak's public hostname. Defaults to
     * {@code <url>/realms/<auth-realm>}.
     */
    Optional<String> issuer();

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
     * Whether registered {@code KeycloakSystemRepository}s may add systems at runtime.
     * Off by default: a repository found on the class path is then listed in the log but
     * not asked, so an extension cannot point the server at a Keycloak it was not
     * configured for. Each repository can additionally be switched with
     * {@code kc-mcp.spi.<id>.enabled}.
     */
    @WithDefault("false")
    boolean dynamicSystems();

    /**
     * JSON file the built-in file repository reads ({@code {"systems": [...]}}), re-read
     * when it changes; needs {@code kc-mcp.dynamic-systems=true}. A relative path is
     * resolved like {@code kc-mcp.providers-dir}.
     */
    Optional<String> systemsFile();

    /**
     * Whether the top-level / {@code kc-mcp.systems.*} settings define systems.
     * {@code false} for deployments whose systems come from sources only; then at least
     * one source must be registered and enabled.
     */
    @WithDefault("true")
    boolean staticSystems();

    /**
     * Where the static configuration ranks among the system repositories (lower is asked
     * first; registered repositories default to 0). The default puts the static
     * configuration first, so a repository cannot redefine a configured system; raise it
     * above the repositories' order to let them take precedence.
     */
    @WithDefault("-1000")
    int staticSystemsOrder();

    /**
     * Directory of the built-in
     * {@link com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault}: one PEM file per
     * system with the {@code private_key_jwt} key generated for it, used when no
     * {@code kc-mcp.jwt.key-file} / {@code keystore-file} is configured. A relative path
     * is resolved like {@code kc-mcp.providers-dir}.
     */
    @WithDefault("data/keys")
    String keysDir();

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

    /**
     * Hosts the server may talk to: every configured Keycloak URL (top level and per
     * system) must match one of these patterns, checked at startup. Pattern
     * {@code [scheme://]host[:port]} with {@code *} wildcards, e.g.
     * {@code *.example.com}, {@code https://sso-*.corp.example.org},
     * {@code localhost:8080}. Empty = no restriction.
     */
    Optional<List<String>> allowedHosts();

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
     * Also return every tool result as MCP {@code structuredContent} (the JSON object
     * next to the text block), so clients can render it without parsing text.
     */
    @WithDefault("true")
    boolean structuredContent();

    /**
     * Per tool-provider settings: {@code kc-mcp.spi.<provider-id>.<key>=value} (env
     * {@code KC_MCP_SPI_<ID>_<KEY>}). {@code enabled=false} switches a provider off.
     */
    Map<String, Map<String, String>> spi();

    /** Elicitation / confirmation prompt timeout in seconds. */
    @WithDefault("120")
    int confirmTimeoutSeconds();

    /**
     * Directory with extension jars ({@code ToolProvider}, {@code PromptProvider},
     * {@code AccessCheck}, {@code Confirmer}, {@code AuditListener} implementations
     * registered through {@code META-INF/services}), like Keycloak's {@code providers/}.
     * A relative path is resolved against the directory of the application jar when the
     * server runs packaged, else the working directory. A missing directory loads
     * nothing. JVM mode only.
     */
    @WithDefault("providers")
    String providersDir();

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

        /** Keycloak version of this system; see {@link McpServerConfig#version()}. */
        Optional<String> version();

        /** Issuer of this system's auth realm; see {@link McpServerConfig#issuer()}. */
        Optional<String> issuer();
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
