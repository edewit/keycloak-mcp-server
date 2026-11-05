package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

/**
 * Resolved connection settings of one Keycloak system (per-system values with top-level
 * fallbacks). The {@link #name()} is the technical key: the {@code system} argument, the
 * entry path {@code /mcp/systems/<name>}, the key in the vault; {@link #displayName()} is
 * a label for people. A {@link #clientSecret()} or {@link #password()} of the form
 * {@code vault:<secret name>} is a reference the server resolves against the
 * {@link KeyVault} before connecting.
 */
public record KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
        Optional<String> clientId, Optional<String> clientSecret, Optional<String> username, Optional<String> password,
        Optional<String> defaultRealm, Set<String> allowedRealms, Optional<String> version, Optional<String> issuer,
        Optional<String> displayName) {

    public static final String DEFAULT_NAME = "default";

    /**
     * Prefix of a secret value that names a {@link KeyVault} secret instead of holding
     * one.
     */
    public static final String VAULT_REF = "vault:";

    public KeycloakSystem {
        displayName = displayName == null ? Optional.empty() : displayName.map(String::trim).filter(v -> !v.isEmpty());
    }

    /** Without a display name. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, Optional.empty());
    }

    /** Without an issuer: the audience of client assertions is derived from the URL. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, Optional.empty());
    }

    /**
     * The issuer of the auth realm as Keycloak states it, the {@code aud} of
     * {@code private_key_jwt} client assertions: the configured {@code issuer} when the
     * server is reached through an internal URL that differs from its public hostname,
     * else {@code <url>/realms/<auth realm>}.
     */
    /**
     * The base URL users and browsers reach this Keycloak at: derived from the configured
     * issuer when it names the auth realm ({@code https://sso.example.com/realms/master}
     * -> {@code https://sso.example.com}), else the {@link #url()} the server itself
     * uses.
     */
    public String publicUrl() {
        String suffix = "/realms/" + authRealm;
        return issuer.map(String::trim)
            .filter(i -> i.endsWith(suffix))
            .map(i -> i.substring(0, i.length() - suffix.length()))
            .orElseGet(() -> url.endsWith("/") ? url.substring(0, url.length() - 1) : url);
    }

    public String assertionAudience() {
        return issuer.filter(v -> !v.isBlank()).orElseGet(() -> {
            String base = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
            return base + "/realms/" + authRealm;
        });
    }

    public static KeycloakSystem fromTopLevel(McpServerConfig c) {
        return resolve(DEFAULT_NAME, c, null);
    }

    public static KeycloakSystem resolve(String name, McpServerConfig c, McpServerConfig.SystemSettings s) {
        Optional<String> clientSecret = pick(s == null ? Optional.empty() : s.clientSecret(), c.clientSecret());
        ClientAuth auth = pick(s == null ? Optional.empty() : s.clientAuth(), c.clientAuth()).orElseGet(() -> {
            if (clientSecret.filter(v -> !v.isBlank()).isPresent()) {
                return ClientAuth.CLIENT_SECRET;
            }
            if (c.jwt().keyFile().isPresent() || c.jwt().keystoreFile().isPresent()) {
                return ClientAuth.PRIVATE_KEY_JWT;
            }
            return ClientAuth.NONE;
        });
        List<String> realms = pick(s == null ? Optional.empty() : s.allowedRealms(), c.allowedRealms())
            .orElse(List.of());
        return new KeycloakSystem(name, s == null ? c.url() : s.url().orElse(c.url()),
                s == null ? c.grantType() : s.grantType().orElse(c.grantType()), auth,
                s == null ? c.authRealm() : s.authRealm().orElse(c.authRealm()),
                pick(s == null ? Optional.empty() : s.clientId(), c.clientId()), clientSecret,
                pick(s == null ? Optional.empty() : s.username(), c.username()),
                pick(s == null ? Optional.empty() : s.password(), c.password()),
                pick(s == null ? Optional.empty() : s.defaultRealm(), c.defaultRealm()),
                Set.copyOf(realms.stream().map(String::trim).filter(v -> !v.isEmpty()).toList()),
                pick(s == null ? Optional.empty() : s.version(), c.version()).map(String::trim)
                    .filter(v -> !v.isEmpty()),
                pick(s == null ? Optional.empty() : s.issuer(), c.issuer()).map(String::trim)
                    .filter(v -> !v.isEmpty()));
    }

    public KeycloakSystem withDisplayName(String label) {
        return new KeycloakSystem(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username,
                password, defaultRealm, allowedRealms, version, issuer, Optional.ofNullable(label));
    }

    public KeycloakSystem withClientSecret(Optional<String> secret) {
        return new KeycloakSystem(name, url, grantType, clientAuth, authRealm, clientId, secret, username, password,
                defaultRealm, allowedRealms, version, issuer, displayName);
    }

    public KeycloakSystem withPassword(Optional<String> newPassword) {
        return new KeycloakSystem(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username,
                newPassword, defaultRealm, allowedRealms, version, issuer, displayName);
    }

    /**
     * Whether a secret value is a {@code vault:} reference rather than the secret itself.
     */
    public static boolean isVaultRef(String value) {
        return value != null && value.startsWith(VAULT_REF) && value.length() > VAULT_REF.length();
    }

    /** The secret name of a {@code vault:} reference. */
    public static String vaultRefName(String value) {
        return value.substring(VAULT_REF.length()).trim();
    }

    private static <T> Optional<T> pick(Optional<T> specific, Optional<T> fallback) {
        return specific.isPresent() ? specific : fallback;
    }

    /**
     * Whether the settings contain something to log in with (a secret / key for
     * client_credentials, a user for password).
     */
    public boolean hasCredentials() {
        return switch (grantType) {
            case CLIENT_CREDENTIALS -> clientAuth != ClientAuth.NONE;
            case PASSWORD -> username.filter(v -> !v.isBlank()).isPresent();
        };
    }

    public boolean realmAllowed(String realm) {
        return allowedRealms.isEmpty() || allowedRealms.contains(realm);
    }
}
