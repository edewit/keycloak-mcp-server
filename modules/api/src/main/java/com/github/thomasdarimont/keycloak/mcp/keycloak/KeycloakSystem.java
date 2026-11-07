package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Collection;
import java.util.LinkedHashSet;
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
        Optional<String> displayName, Optional<String> description) {

    public static final String DEFAULT_NAME = "default";

    /**
     * Prefix of a secret value that names a {@link KeyVault} secret instead of holding
     * one.
     */
    public static final String VAULT_REF = "vault:";

    public KeycloakSystem {
        displayName = displayName == null ? Optional.empty() : displayName.map(String::trim).filter(v -> !v.isEmpty());
        description = description == null ? Optional.empty() : description.map(String::trim).filter(v -> !v.isEmpty());
    }

    /** Without a description. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, Optional.empty());
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

    /**
     * The issuer of the auth realm as Keycloak states it, the {@code aud} of
     * {@code private_key_jwt} client assertions: the configured {@code issuer} when the
     * server is reached through an internal URL that differs from its public hostname,
     * else {@code <url>/realms/<auth realm>}.
     */
    public String assertionAudience() {
        return issuer.filter(v -> !v.isBlank()).orElseGet(() -> {
            String base = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
            return base + "/realms/" + authRealm;
        });
    }

    /**
     * The system {@code name} from its block and the shared defaults: every value the
     * block leaves out comes from {@code kc-mcp.system-defaults.*}, then from the
     * built-in default ({@code client_credentials}, auth realm {@code master}, client
     * auth inferred from a secret or the configured JWT key). The block must name a
     * {@code url}.
     */
    public static KeycloakSystem resolve(String name, McpServerConfig c, McpServerConfig.SystemSettings s) {
        McpServerConfig.SystemSettings d = c.systemDefaults();
        String url = s.url()
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElseThrow(() -> new IllegalStateException("kc-mcp.systems." + name + ".url is not set"));
        Optional<String> clientSecret = pick(s.clientSecret(), d.clientSecret());
        ClientAuth auth = pick(s.clientAuth(), d.clientAuth()).orElseGet(() -> {
            if (clientSecret.filter(v -> !v.isBlank()).isPresent()) {
                return ClientAuth.CLIENT_SECRET;
            }
            if (c.jwt().keyFile().isPresent() || c.jwt().keystoreFile().isPresent()) {
                return ClientAuth.PRIVATE_KEY_JWT;
            }
            return ClientAuth.NONE;
        });
        List<String> realms = pick(s.allowedRealms(), d.allowedRealms()).orElse(List.of());
        return new KeycloakSystem(name, url, pick(s.grantType(), d.grantType()).orElse(GrantType.CLIENT_CREDENTIALS),
                auth, pick(s.authRealm(), d.authRealm()).orElse("master"), pick(s.clientId(), d.clientId()),
                clientSecret, pick(s.username(), d.username()), pick(s.password(), d.password()),
                pick(s.defaultRealm(), d.defaultRealm()),
                Set.copyOf(realms.stream().map(String::trim).filter(v -> !v.isEmpty()).toList()),
                pick(s.version(), d.version()).map(String::trim).filter(v -> !v.isEmpty()),
                pick(s.issuer(), d.issuer()).map(String::trim).filter(v -> !v.isEmpty()));
    }

    public KeycloakSystem withDisplayName(String label) {
        return toBuilder().displayName(label).build();
    }

    /** A free text for people: what this Keycloak is, who owns it. */
    public KeycloakSystem withDescription(String text) {
        return toBuilder().description(text).build();
    }

    public KeycloakSystem withClientSecret(Optional<String> secret) {
        return toBuilder().clientSecret(secret.orElse(null)).build();
    }

    public KeycloakSystem withPassword(Optional<String> newPassword) {
        return toBuilder().password(newPassword.orElse(null)).build();
    }

    /** A builder with this system's values, for a changed copy. */
    public Builder toBuilder() {
        return new Builder().name(name)
            .url(url)
            .grantType(grantType)
            .clientAuth(clientAuth)
            .authRealm(authRealm)
            .clientId(clientId.orElse(null))
            .clientSecret(clientSecret.orElse(null))
            .username(username.orElse(null))
            .password(password.orElse(null))
            .defaultRealm(defaultRealm.orElse(null))
            .allowedRealms(allowedRealms)
            .version(version.orElse(null))
            .issuer(issuer.orElse(null))
            .displayName(displayName.orElse(null))
            .description(description.orElse(null));
    }

    /**
     * Builds a system without juggling {@code Optional}s: every setter takes a plain
     * value, {@code null} or blank meaning unset. Defaults: {@code client_credentials},
     * {@code private_key_jwt}, auth realm {@code master}, no allowed realms (all).
     *
     * <pre>
     * KeycloakSystem.builder("acme", "https://sso.acme.example")
     *     .clientId("keycloak-mcp-server").defaultRealm("acme-dev").allowedRealm("acme-dev")
     *     .displayName("ACME Corp.").build();
     * </pre>
     */
    public static Builder builder(String name, String url) {
        return new Builder().name(name).url(url);
    }

    public static final class Builder {
        private String name;
        private String url;
        private GrantType grantType = GrantType.CLIENT_CREDENTIALS;
        private ClientAuth clientAuth = ClientAuth.PRIVATE_KEY_JWT;
        private String authRealm = "master";
        private String clientId;
        private String clientSecret;
        private String username;
        private String password;
        private String defaultRealm;
        private final Set<String> allowedRealms = new LinkedHashSet<>();
        private String version;
        private String issuer;
        private String displayName;
        private String description;

        private Builder() {
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder grantType(GrantType grantType) {
            this.grantType = grantType == null ? GrantType.CLIENT_CREDENTIALS : grantType;
            return this;
        }

        public Builder clientAuth(ClientAuth clientAuth) {
            this.clientAuth = clientAuth == null ? ClientAuth.PRIVATE_KEY_JWT : clientAuth;
            return this;
        }

        public Builder authRealm(String authRealm) {
            this.authRealm = authRealm == null || authRealm.isBlank() ? "master" : authRealm.trim();
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /** The secret itself or a {@code vault:<name>} reference. */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        /** The password itself or a {@code vault:<name>} reference. */
        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder defaultRealm(String defaultRealm) {
            this.defaultRealm = defaultRealm;
            return this;
        }

        /** Replaces the allowed realms; empty means every realm. */
        public Builder allowedRealms(Collection<String> realms) {
            allowedRealms.clear();
            if (realms != null) {
                realms.stream().filter(r -> r != null && !r.isBlank()).map(String::trim).forEach(allowedRealms::add);
            }
            return this;
        }

        /** Adds one allowed realm. */
        public Builder allowedRealm(String realm) {
            if (realm != null && !realm.isBlank()) {
                allowedRealms.add(realm.trim());
            }
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        /**
         * The realm's public issuer URL when it differs from
         * {@code <url>/realms/<auth realm>}.
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder displayName(String displayName) {
            this.displayName = displayName;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /** @throws IllegalArgumentException without a name or url */
        public KeycloakSystem build() {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("A system needs a name");
            }
            if (url == null || url.isBlank()) {
                throw new IllegalArgumentException("The system '" + name + "' needs a url");
            }
            return new KeycloakSystem(name.trim(), url.trim(), grantType, clientAuth, authRealm, text(clientId),
                    text(clientSecret), text(username), text(password), text(defaultRealm), Set.copyOf(allowedRealms),
                    text(version), text(issuer), text(displayName), text(description));
        }

        private static Optional<String> text(String value) {
            return value == null || value.isBlank() ? Optional.empty() : Optional.of(value.trim());
        }
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
