package org.keycloak.mcp.server.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import jakarta.ws.rs.client.Client;

import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.mcp.config.ClientAuth;
import org.keycloak.mcp.config.GrantType;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.mcp.keycloak.KeycloakSystem;
import org.keycloak.mcp.keycloak.ScopeEvaluation;

/**
 * The server's {@link KeycloakAdmin}: a lazily built admin client for one
 * {@link KeycloakSystem} (password, client secret or private_key_jwt) plus the per-caller
 * clients of delegation mode {@code forward}. Instances are managed by
 * {@link DefaultKeycloakSystems}.
 */
public class DefaultKeycloakAdmin implements KeycloakAdmin {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakAdmin.class);
    /**
     * Upper bound of cached per-caller clients; beyond it the cache is dropped and
     * rebuilt on demand.
     */
    static final int MAX_DELEGATES = 256;

    private record Delegate(DefaultKeycloakAdmin admin, long expiresAt) {
    }

    private final KeycloakSystem system;
    private final JwtKeyMaterial jwtKeys;
    private final ReentrantLock initLock = new ReentrantLock();
    private volatile Keycloak keycloak;
    private volatile ClientAssertionTokenManager jwtTokens;
    /** Set on instances returned by {@link #forToken}: the forwarded caller token. */
    private final String forwardedToken;
    private final Map<String, Delegate> delegates = new ConcurrentHashMap<>();

    public DefaultKeycloakAdmin(KeycloakSystem system, JwtKeyMaterial jwtKeys) {
        this(system, jwtKeys, null, null);
    }

    private DefaultKeycloakAdmin(KeycloakSystem system, JwtKeyMaterial jwtKeys, Keycloak prebuilt,
            String forwardedToken) {
        this.system = system;
        this.jwtKeys = jwtKeys;
        this.keycloak = prebuilt;
        this.forwardedToken = forwardedToken;
    }

    /**
     * An admin client of the same system that sends the given caller token instead of the
     * server's credentials (delegation mode {@code forward}). Instances are cached per
     * token until the token expires.
     */
    @Override
    public KeycloakAdmin forToken(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new IllegalArgumentException("caller token required");
        }
        long now = System.currentTimeMillis();
        Delegate d = delegates.get(bearerToken);
        if (d != null && d.expiresAt() > now) {
            return d.admin();
        }
        if (delegates.size() >= MAX_DELEGATES) {
            purgeDelegates(now, true);
        }
        else if (d != null) {
            purgeDelegates(now, false);
        }
        return delegates.compute(bearerToken, (k, old) -> {
            if (old != null && old.expiresAt() > now) {
                return old;
            }
            if (old != null) {
                old.admin().close();
            }
            Keycloak k2 = KeycloakBuilder.builder()
                .serverUrl(system.url())
                .realm(system.authRealm())
                .clientId(system.clientId().filter(v -> !v.isBlank()).orElse("keycloak-mcp-server"))
                .authorization(bearerToken)
                .build();
            return new Delegate(new DefaultKeycloakAdmin(system, jwtKeys, k2, bearerToken), expiryOf(bearerToken, now));
        }).admin();
    }

    /**
     * Whether this instance forwards a caller's token rather than using the server's
     * credentials.
     */
    @Override
    public boolean isDelegated() {
        return forwardedToken != null;
    }

    private void purgeDelegates(long now, boolean all) {
        for (Map.Entry<String, Delegate> e : delegates.entrySet()) {
            if (all || e.getValue().expiresAt() <= now) {
                if (delegates.remove(e.getKey(), e.getValue())) {
                    e.getValue().admin().close();
                }
            }
        }
    }

    /**
     * {@code exp} of a JWT in millis; tokens without a readable {@code exp} are kept for
     * five minutes.
     */
    static long expiryOf(String jwt, long now) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                var payload = new io.vertx.core.json.JsonObject(
                        new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
                Long exp = payload.getLong("exp");
                if (exp != null) {
                    return exp * 1000;
                }
            }
        }
        catch (RuntimeException e) {
            LOG.debugf("Cannot read token expiry: %s", e.toString());
        }
        return now + 5 * 60_000L;
    }

    @Override
    public KeycloakSystem system() {
        return system;
    }

    @Override
    public String name() {
        return system.name();
    }

    /**
     * Lazily builds the client; uses a lock rather than {@code synchronized} so virtual
     * threads are not pinned.
     */
    @Override
    public Keycloak client() {
        Keycloak k = keycloak;
        if (k != null) {
            return k;
        }
        initLock.lock();
        try {
            k = keycloak;
            if (k == null) {
                k = build();
                keycloak = k;
            }
            return k;
        }
        finally {
            initLock.unlock();
        }
    }

    private Keycloak build() {
        GrantType grant = system.grantType();
        ClientAuth auth = system.clientAuth();
        LOG.infof("Connecting to Keycloak system '%s' at %s (grant=%s, clientAuth=%s, authRealm=%s)", system.name(),
                system.url(), grant.oauthValue(), auth, system.authRealm());
        if (grant == GrantType.CLIENT_CREDENTIALS && auth == ClientAuth.NONE) {
            throw new IllegalStateException("Missing configuration: the client_credentials grant needs "
                    + "'kc-mcp.client-secret' or a private_key_jwt key ('kc-mcp.jwt.key-file' / 'kc-mcp.jwt.keystore-file')");
        }
        String clientId = system.clientId()
            .filter(v -> !v.isBlank())
            .orElseGet(() -> grant == GrantType.PASSWORD && auth == ClientAuth.NONE ? "admin-cli" : null);
        if (clientId == null) {
            throw new IllegalStateException("Missing configuration 'kc-mcp.client-id'");
        }
        String username = grant == GrantType.PASSWORD ? require(system.username(), "kc-mcp.username") : null;
        String password = grant == GrantType.PASSWORD ? require(system.password(), "kc-mcp.password") : null;

        KeycloakBuilder builder = KeycloakBuilder.builder()
            .serverUrl(system.url())
            .realm(system.authRealm())
            .clientId(clientId);
        switch (auth) {
            case NONE -> builder.grantType(grant.oauthValue()).username(username).password(password);
            case CLIENT_SECRET -> builder.grantType(grant.oauthValue())
                .username(username)
                .password(password)
                .clientSecret(require(system.clientSecret(), "kc-mcp.client-secret"));
            case PRIVATE_KEY_JWT -> {
                Client restClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                Client tokenClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                jwtTokens = new ClientAssertionTokenManager(tokenClient, system.url(), system.authRealm(), clientId,
                        jwtKeys.signer(), jwtKeys.assertionLifespan(), grant, username, password);
                restClient.register(new PrivateKeyJwtAuthFilter(jwtTokens));
                // A fixed placeholder token makes the admin client skip its own
                // TokenManager; the filter above
                // runs later in the chain and replaces the Authorization header with a
                // real token.
                builder.resteasyClient(restClient).authorization(PrivateKeyJwtAuthFilter.PLACEHOLDER);
            }
        }
        return builder.build();
    }

    private static String require(java.util.Optional<String> value, String key) {
        return value.filter(v -> !v.isBlank())
            .orElseThrow(() -> new IllegalStateException("Missing configuration '" + key + "' for auth mode"));
    }

    /**
     * Current admin access token (triggers a login on first use); the caller's token for
     * a delegated instance.
     */
    @Override
    public String accessToken() {
        if (forwardedToken != null) {
            return forwardedToken;
        }
        Keycloak k = client();
        ClientAssertionTokenManager jwt = jwtTokens;
        if (jwt != null) {
            return jwt.accessToken();
        }
        return k.tokenManager().getAccessTokenString();
    }

    @Override
    public String authRealm() {
        return system.authRealm();
    }

    /**
     * Scope evaluation endpoints (no admin client binding exists); authenticated like
     * every other call.
     */
    @Override
    public ScopeEvaluation scopeEvaluation() {
        return client().proxy(ScopeEvaluation.class, java.net.URI.create(system.url()));
    }

    @Override
    public RealmResource realm(String realm) {
        return client().realm(realm);
    }

    @Override
    public void close() {
        purgeDelegates(Long.MAX_VALUE, true);
        Keycloak k = keycloak;
        if (k != null) {
            try {
                k.close();
            }
            catch (RuntimeException e) {
                LOG.debug("Closing admin client failed", e);
            }
        }
        if (jwtTokens != null) {
            jwtTokens.close();
        }
    }
}
