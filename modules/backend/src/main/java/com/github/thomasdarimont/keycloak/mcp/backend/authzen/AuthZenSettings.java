package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * The AuthZEN policy decision point a system's tool calls are evaluated at: the defaults
 * of {@code kc-mcp.spi.authorization-engine.authzen.*} with the system's
 * {@code authorization} settings on top ({@link #merge}).
 *
 * @param enabled whether this system's calls are evaluated
 * @param url the PDP's evaluation endpoint, e.g.
 * {@code https://pdp.example/access/v1/evaluation}; may contain {@code {system}} and
 * {@code {realm}} (URL-encoded, {@code _} for a global tool's realm); {@code null}: the
 * system has no PDP
 * @param auth how the server authenticates at the PDP
 * @param headerName {@code auth=header}: the request header, {@code Authorization} by
 * default
 * @param headerValue {@code auth=header}: its value as sent, e.g. {@code Bearer abc}
 * @param tokenUrl {@code auth=client-credentials}: the token endpoint
 * @param clientId {@code auth=client-credentials}: the client
 * @param clientAuth {@code auth=client-credentials}: how the client authenticates, a
 * {@code ClientAuthenticatorFactory} id: {@code client_secret_basic} (default, with
 * {@code client-secret}), {@code client_secret_post}, {@code private_key_jwt}
 * ({@code jwt-*} settings or the system's signing key) or an extension's
 * @param scope {@code auth=client-credentials}: requested scope, none by default
 * @param onError what a PDP that cannot be reached or answers nonsense means:
 * {@code deny} (default) or {@code allow}
 * @param sendArgs whether the call's arguments go into {@code context.args} (sensitive
 * ones are always masked)
 * @param connectTimeout {@code null} for {@code kc-mcp.http.connect-timeout}
 * @param readTimeout 5 seconds unless set: every tool call waits for the PDP
 * @param tlsConfigurationName named TLS configuration ({@code quarkus.tls.<name>.*}) for
 * the calls to the PDP; {@code null} for the JVM's default trust
 */
public record AuthZenSettings(boolean enabled, String url, Auth auth, String headerName, String headerValue,
        URI tokenUrl, String clientId, String clientAuth, String scope, OnError onError, boolean sendArgs,
        Duration connectTimeout, Duration readTimeout, String tlsConfigurationName) {

    public static final String ID = "authzen";
    static final String PREFIX = "kc-mcp.spi.authorization-engine." + ID + ".";
    /**
     * Settings of the check as a whole; everything else is a PDP default a system's
     * {@code authorization} block can override.
     */
    static final Set<String> GLOBAL_KEYS = Set.of("enabled", "default", "systems-without-pdp", "required", "provider");

    public enum Auth {
        NONE, HEADER, CLIENT_CREDENTIALS,
        /**
         * A token from the Keycloak system's own token endpoint, requested with the
         * system's own client (its secret or {@code private_key_jwt} key) and the PDP's
         * {@code scope}: no credentials of its own, the PDP trusts the system's issuer.
         * Never the system's Admin API token, which would let the PDP administer
         * Keycloak.
         */
        SYSTEM_CLIENT
    }

    public enum OnError {
        DENY, ALLOW
    }

    /**
     * Whether a system whose {@code authorization} block says nothing is evaluated:
     * {@code off} (default) or {@code on}.
     */
    public enum Default {
        OFF, ON;

        static Default from(ProviderConfig config) {
            return config.readEnum(DEFAULT, Default.class);
        }
    }

    /** What a system without a PDP means: {@code deny} (default) or {@code skip}. */
    public enum WithoutPdp {
        DENY, SKIP;

        static WithoutPdp from(ProviderConfig config) {
            return config.readEnum(SYSTEMS_WITHOUT_PDP, WithoutPdp.class);
        }
    }

    public static final ConfigProperty DEFAULT = ConfigProperty.choice("default", Default.class)
        .withAliases("false", "off", "true", "on")
        .withDefault("off");

    public static final ConfigProperty SYSTEMS_WITHOUT_PDP = ConfigProperty
        .choice("systems-without-pdp", WithoutPdp.class)
        .withAliases("allow", "skip")
        .withDefault("deny");

    public static final ConfigProperty URL = ConfigProperty.string("url");

    public static final ConfigProperty AUTH = ConfigProperty.choice("auth", Auth.class)
        .withAliases("api-key", "header", "client_credentials", "client-credentials", "system_client", "system-client")
        .withDefault("none");

    public static final ConfigProperty HEADER_NAME = ConfigProperty.string("header-name").withDefault("Authorization");

    public static final ConfigProperty HEADER_VALUE = ConfigProperty.string("header-value").asConfidential();

    public static final ConfigProperty TOKEN_URL = ConfigProperty.url("token-url");

    public static final ConfigProperty CLIENT_ID = ConfigProperty.string("client-id");

    public static final ConfigProperty CLIENT_AUTH = ConfigProperty.string("client-auth")
        .withDefault("client_secret_basic");

    public static final ConfigProperty SCOPE = ConfigProperty.string("scope");

    public static final ConfigProperty ON_ERROR = ConfigProperty.choice("on-error", OnError.class).withDefault("deny");

    public static final ConfigProperty SEND_ARGS = ConfigProperty.bool("send-args").withDefault("true");

    public static final ConfigProperty CONNECT_TIMEOUT = ConfigProperty.duration("connect-timeout");

    public static final ConfigProperty READ_TIMEOUT = ConfigProperty.duration("read-timeout").withDefault("5s");

    public static final ConfigProperty TLS_CONFIGURATION_NAME = ConfigProperty.string("tls-configuration-name");

    /** The engine's own settings; the client authenticators' come on top. */
    public static final ConfigSpec CONFIG_SPEC = ConfigSpec
        .of(DEFAULT, SYSTEMS_WITHOUT_PDP, URL, AUTH, HEADER_NAME, HEADER_VALUE, TOKEN_URL, CLIENT_ID, CLIENT_AUTH,
                SCOPE, ON_ERROR, SEND_ARGS, CONNECT_TIMEOUT, READ_TIMEOUT, TLS_CONFIGURATION_NAME)
        .withHints(ConfigHint.group("evaluation", DEFAULT.name(), SYSTEMS_WITHOUT_PDP.name()),
                ConfigHint.group("pdp", URL.name(), ON_ERROR.name(), SEND_ARGS.name(), CONNECT_TIMEOUT.name(),
                        READ_TIMEOUT.name(), TLS_CONFIGURATION_NAME.name()),
                ConfigHint.group("authentication", AUTH.name(), HEADER_NAME.name(), HEADER_VALUE.name(),
                        TOKEN_URL.name(), CLIENT_ID.name(), CLIENT_AUTH.name(), SCOPE.name()),
                // presentational: a PDP URL is needed too, and a system may bring it
                // (validate enforces them with the URL)
                ConfigHint.when(HEADER_NAME.name()).is(AUTH.name(), "header"),
                ConfigHint.when(HEADER_VALUE.name()).is(AUTH.name(), "header"),
                ConfigHint.when(TOKEN_URL.name()).is(AUTH.name(), "client-credentials"),
                ConfigHint.when(CLIENT_ID.name()).is(AUTH.name(), "client-credentials"),
                ConfigHint.when(CLIENT_AUTH.name()).is(AUTH.name(), "client-credentials"),
                ConfigHint.when(SCOPE.name()).is(AUTH.name(), "client-credentials", "system-client"));

    /** Problem code: a URL that is not http(s); args {@code key}, {@code value}. */
    public static final String NOT_HTTP_URL = "authzen.not-http-url";

    /**
     * Problem code: {@code auth=header} without {@code header-value}; args {@code key}.
     */
    public static final String HEADER_VALUE_NEEDED = "authzen.header-value-needed";

    /**
     * Problem code: {@code auth=client-credentials} without {@code token-url} or
     * {@code client-id}; args {@code key}.
     */
    public static final String CLIENT_CREDENTIALS_INCOMPLETE = "authzen.client-credentials-incomplete";

    public static final AuthZenSettings DISABLED = new AuthZenSettings(false, null, Auth.NONE, null, null, null, null,
            null, null, OnError.DENY, true, null, null, null);

    /** Whether this system's calls go to a PDP. */
    public boolean configured() {
        return enabled && url != null;
    }

    /** The evaluation endpoint for one call. */
    URI endpoint(String system, String realm) {
        return URI.create(url.replace("{system}", enc(system == null ? "_" : system))
            .replace("{realm}", enc(realm == null ? "_" : realm)));
    }

    /**
     * The settings of a PDP: the check's own defaults with the {@code authzen} block of
     * the effective authorization (the system's, a realm's on top) over them. Only called
     * for calls that are evaluated, so the result is always enabled.
     */
    static ProviderConfig merge(ProviderConfig config, Map<String, String> system) {
        Map<String, String> merged = new LinkedHashMap<>();
        config.asMap().forEach((k, v) -> {
            if (!GLOBAL_KEYS.contains(k)) {
                merged.put(k, v);
            }
        });
        if (system != null) {
            merged.putAll(system);
        }
        merged.put("enabled", "true");
        return config.withValues(merged);
    }

    /** Where a system's settings are configured, for error messages. */
    static String systemPrefix(String system) {
        return system == null ? PREFIX : "kc-mcp.systems." + system + ".authorization." + ID + ".";
    }

    /**
     * {@code enabled=false}: not evaluated. Enabled without a URL: a system without a PDP
     * ({@link #configured()} false), which {@code systems-without-pdp} decides about.
     *
     * @param where the system the settings are for, for error messages; {@code null} for
     * the defaults
     */
    public static AuthZenSettings from(ProviderConfig settings, String where) {
        if (!settings.getBoolean("enabled", false)) {
            return DISABLED;
        }
        // a system's settings are named where the system has them, the check's defaults
        // may fill them
        ProviderConfig config = settings.describedAs(systemPrefix(where));
        List<ConfigProblem> errors = new ArrayList<>(ConfigProblem.errors(config.problems()));
        if (errors.isEmpty()) {
            errors.addAll(ConfigProblem.errors(rules(config, where)));
        }
        if (!errors.isEmpty()) {
            throw new IllegalStateException(ConfigProblem.describe(errors));
        }
        String url = trimmed(config.readString(URL));
        if (url == null) {
            return new AuthZenSettings(true, null, Auth.NONE, null, null, null, null, null, null, OnError.DENY, true,
                    null, null, null);
        }
        return new AuthZenSettings(true, url, config.readEnum(AUTH, Auth.class), config.readString(HEADER_NAME),
                trimmed(config.readString(HEADER_VALUE)), config.readUrl(TOKEN_URL),
                trimmed(config.readString(CLIENT_ID)), config.readString(CLIENT_AUTH).trim(),
                trimmed(config.readString(SCOPE)), config.readEnum(ON_ERROR, OnError.class),
                config.readBoolean(SEND_ARGS), config.readDuration(CONNECT_TIMEOUT), config.readDuration(READ_TIMEOUT),
                trimmed(config.readString(TLS_CONFIGURATION_NAME)));
    }

    /**
     * The rules between the settings of a PDP, once it has a URL (without one the system
     * has no PDP, which {@code systems-without-pdp} decides about): http(s) URLs,
     * {@code auth=header} with a {@code header-value}, {@code auth=client-credentials}
     * with {@code token-url} and {@code client-id}. The settings must have passed the
     * spec's checks.
     *
     * @param where the system the settings are for, for the messages; {@code null} for
     * the defaults
     */
    static List<ConfigProblem> rules(ProviderConfig config, String where) {
        String url = trimmed(config.readString(URL));
        if (url == null) {
            return List.of();
        }
        String p = config.key("");
        String of = where == null ? "" : " (or " + PREFIX + "* for every system)";
        List<ConfigProblem> problems = new ArrayList<>();
        // placeholders ({realm.name}, ...) are the access check chain's to fill per call
        checkUrl(url.replaceAll("\\{[^}]*}", "x"), URL.name(), p + URL.name(), of).ifPresent(problems::add);
        URI token = config.readUrl(TOKEN_URL);
        if (token != null) {
            checkUrl(token.toString(), TOKEN_URL.name(), p + TOKEN_URL.name(), of).ifPresent(problems::add);
        }
        Auth auth = config.readEnum(AUTH, Auth.class);
        if (auth == Auth.HEADER && trimmed(config.readString(HEADER_VALUE)) == null) {
            problems.add(
                    ConfigProblem
                        .error(HEADER_VALUE_NEEDED, p + "auth=header needs " + p + HEADER_VALUE.name() + of,
                                AUTH.name(), HEADER_VALUE.name())
                        .withArg("key", p + HEADER_VALUE.name()));
        }
        if (auth == Auth.CLIENT_CREDENTIALS && (token == null || trimmed(config.readString(CLIENT_ID)) == null)) {
            problems
                .add(ConfigProblem
                    .error(CLIENT_CREDENTIALS_INCOMPLETE,
                            p + "auth=client-credentials needs " + p + TOKEN_URL.name() + " and " + p + CLIENT_ID.name()
                                    + of,
                            AUTH.name(), TOKEN_URL.name(), CLIENT_ID.name())
                    .withArg("key", p + AUTH.name()));
        }
        return problems;
    }

    private static Optional<ConfigProblem> checkUrl(String v, String name, String key, String of) {
        try {
            URI u = URI.create(v);
            if ("https".equalsIgnoreCase(u.getScheme()) || "http".equalsIgnoreCase(u.getScheme())) {
                return Optional.empty();
            }
        }
        catch (IllegalArgumentException e) {
            // not a URL at all: the same problem
        }
        return Optional
            .of(ConfigProblem.error(NOT_HTTP_URL, key + " must be an http(s) URL, not '" + v + "'" + of, name)
                .withArg("key", key)
                .withArg("value", v));
    }

    private static String trimmed(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** For the startup log: where the calls go, or what happens without a PDP. */
    String describe(WithoutPdp withoutPdp) {
        return configured() ? url + " (auth " + auth + ")"
                : "no PDP, calls " + (withoutPdp == WithoutPdp.DENY ? "denied" : "allowed");
    }

    /** Never prints the secrets. */
    @Override
    public String toString() {
        return "AuthZenSettings[enabled=" + enabled + ", url=" + url + ", auth=" + auth
                + (auth == Auth.CLIENT_CREDENTIALS ? " (" + clientAuth + ")" : "") + ", onError=" + onError
                + ", sendArgs=" + sendArgs + "]";
    }
}
