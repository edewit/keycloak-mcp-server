package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
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
    static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(5);
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
        SYSTEM_CLIENT;

        static Auth parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT).replace('_', '-')) {
                case "none" -> NONE;
                case "header", "api-key" -> HEADER;
                case "client-credentials" -> CLIENT_CREDENTIALS;
                case "system-client" -> SYSTEM_CLIENT;
                default -> throw new IllegalArgumentException(
                        PREFIX + "auth must be none, header, client-credentials or system-client, not '" + v + "'");
            };
        }
    }

    public enum OnError {
        DENY, ALLOW;

        static OnError parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT)) {
                case "deny" -> DENY;
                case "allow" -> ALLOW;
                default ->
                    throw new IllegalArgumentException(PREFIX + "on-error must be deny or allow, not '" + v + "'");
            };
        }
    }

    /**
     * Whether a system whose {@code authorization} block says nothing is evaluated:
     * {@code off} (default) or {@code on}.
     */
    public enum Default {
        OFF, ON;

        static Default from(ProviderConfig config) {
            String v = config.get("default", "off").trim().toLowerCase(Locale.ROOT);
            return switch (v) {
                case "off", "false" -> OFF;
                case "on", "true" -> ON;
                default -> throw new IllegalArgumentException(PREFIX + "default must be on or off, not '" + v + "'");
            };
        }
    }

    /** What a system without a PDP means: {@code deny} (default) or {@code skip}. */
    public enum WithoutPdp {
        DENY, SKIP;

        static WithoutPdp parse(String v) {
            return switch (v.trim().toLowerCase(Locale.ROOT)) {
                case "deny" -> DENY;
                case "skip", "allow" -> SKIP;
                default -> throw new IllegalArgumentException(
                        PREFIX + "systems-without-pdp must be deny or skip, not '" + v + "'");
            };
        }

        static WithoutPdp from(ProviderConfig config) {
            return parse(config.get("systems-without-pdp", "deny"));
        }
    }

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
        return new ProviderConfig(AuthorizationEngine.SPI, ID, merged);
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
    public static AuthZenSettings from(ProviderConfig config, String where) {
        if (!config.getBoolean("enabled", false)) {
            return DISABLED;
        }
        // a system's settings are named where the system has them, the check's defaults
        // may fill them
        String p = systemPrefix(where);
        String of = where == null ? "" : " (or " + PREFIX + "* for every system)";
        String url = config.get("url").map(String::trim).orElse(null);
        if (url == null) {
            return new AuthZenSettings(true, null, Auth.NONE, null, null, null, null, null, null, OnError.DENY, true,
                    null, null, null);
        }
        // placeholders ({realm.name}, ...) are the access check chain's to fill per call
        checkUrl(url.replaceAll("\\{[^}]*}", "x"), p + "url", of);
        Auth auth = Auth.parse(config.get("auth", "none"));
        String headerValue = nonBlank(config.get("header-value"));
        String tokenUrl = nonBlank(config.get("token-url"));
        URI token = tokenUrl == null ? null : checkUrl(tokenUrl, p + "token-url", of);
        String clientId = nonBlank(config.get("client-id"));
        if (auth == Auth.HEADER && headerValue == null) {
            throw new IllegalStateException(p + "auth=header needs " + p + "header-value" + of);
        }
        if (auth == Auth.CLIENT_CREDENTIALS && (token == null || clientId == null)) {
            throw new IllegalStateException(
                    p + "auth=client-credentials needs " + p + "token-url and " + p + "client-id" + of);
        }
        return new AuthZenSettings(true, url, auth, config.get("header-name", "Authorization"), headerValue, token,
                clientId, config.get("client-auth", "client_secret_basic").trim(), nonBlank(config.get("scope")),
                OnError.parse(config.get("on-error", "deny")), config.getBoolean("send-args", true),
                OutboundClients.duration(config.get("connect-timeout"), p + "connect-timeout").orElse(null),
                OutboundClients.duration(config.get("read-timeout"), p + "read-timeout").orElse(DEFAULT_READ_TIMEOUT),
                nonBlank(config.get("tls-configuration-name")));
    }

    private static URI checkUrl(String v, String key, String of) {
        URI u;
        try {
            u = URI.create(v);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(key + " is not a URL: '" + v + "'" + of);
        }
        if (!"https".equalsIgnoreCase(u.getScheme()) && !"http".equalsIgnoreCase(u.getScheme())) {
            throw new IllegalArgumentException(key + " must be an http(s) URL, not '" + v + "'" + of);
        }
        return u;
    }

    private static String nonBlank(Optional<String> v) {
        return v.filter(s -> !s.isBlank()).map(String::trim).orElse(null);
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
