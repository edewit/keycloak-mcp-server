package org.keycloak.mcp.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.mcp.config.ClientAuth;
import org.keycloak.mcp.config.GrantType;
import org.keycloak.mcp.guard.AccessTokenSource;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Lazily built Keycloak admin client for one {@link KeycloakSystem} plus the lookup helpers every tool area needs.
 * Identifier arguments are forgiving: a user may be given by id or username, a client by id or clientId, a group by
 * id, path or name. Instances are managed by {@link KeycloakSystems}.
 */
public class KeycloakAdmin implements AccessTokenSource {

    private static final Logger LOG = Logger.getLogger(KeycloakAdmin.class);
    private static final Pattern UUID = Pattern
            .compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /** Upper bound of cached per-caller clients; beyond it the cache is dropped and rebuilt on demand. */
    static final int MAX_DELEGATES = 256;

    private record Delegate(KeycloakAdmin admin, long expiresAt) {
    }

    private final KeycloakSystem system;
    private final JwtKeyMaterial jwtKeys;
    private final ReentrantLock initLock = new ReentrantLock();
    private volatile Keycloak keycloak;
    private volatile ClientAssertionTokenManager jwtTokens;
    /** Set on instances returned by {@link #forToken}: the forwarded caller token. */
    private final String forwardedToken;
    private final Map<String, Delegate> delegates = new ConcurrentHashMap<>();

    public KeycloakAdmin(KeycloakSystem system, JwtKeyMaterial jwtKeys) {
        this(system, jwtKeys, null, null);
    }

    private KeycloakAdmin(KeycloakSystem system, JwtKeyMaterial jwtKeys, Keycloak prebuilt, String forwardedToken) {
        this.system = system;
        this.jwtKeys = jwtKeys;
        this.keycloak = prebuilt;
        this.forwardedToken = forwardedToken;
    }

    /**
     * An admin client of the same system that sends the given caller token instead of the server's credentials
     * (delegation mode {@code forward}). Instances are cached per token until the token expires.
     */
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
        } else if (d != null) {
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
            return new Delegate(new KeycloakAdmin(system, jwtKeys, k2, bearerToken), expiryOf(bearerToken, now));
        }).admin();
    }

    /** Whether this instance forwards a caller's token rather than using the server's credentials. */
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

    /** {@code exp} of a JWT in millis; tokens without a readable {@code exp} are kept for five minutes. */
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
        } catch (RuntimeException e) {
            LOG.debugf("Cannot read token expiry: %s", e.toString());
        }
        return now + 5 * 60_000L;
    }

    public KeycloakSystem system() {
        return system;
    }

    public String name() {
        return system.name();
    }

    /** Lazily builds the client; uses a lock rather than {@code synchronized} so virtual threads are not pinned. */
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
        } finally {
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
        String clientId = system.clientId().filter(v -> !v.isBlank())
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
            case CLIENT_SECRET -> builder.grantType(grant.oauthValue()).username(username).password(password)
                    .clientSecret(require(system.clientSecret(), "kc-mcp.client-secret"));
            case PRIVATE_KEY_JWT -> {
                Client restClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                Client tokenClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                jwtTokens = new ClientAssertionTokenManager(tokenClient, system.url(), system.authRealm(), clientId,
                        jwtKeys.signer(), jwtKeys.assertionLifespan(), grant, username, password);
                restClient.register(new PrivateKeyJwtAuthFilter(jwtTokens));
                // A fixed placeholder token makes the admin client skip its own TokenManager; the filter above
                // runs later in the chain and replaces the Authorization header with a real token.
                builder.resteasyClient(restClient).authorization(PrivateKeyJwtAuthFilter.PLACEHOLDER);
            }
        }
        return builder.build();
    }

    private static String require(java.util.Optional<String> value, String key) {
        return value.filter(v -> !v.isBlank()).orElseThrow(
                () -> new IllegalStateException("Missing configuration '" + key + "' for auth mode"));
    }

    /** Current admin access token (triggers a login on first use); the caller's token for a delegated instance. */
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

    public RealmResource realm(String realm) {
        return client().realm(realm);
    }

    public static boolean isUuid(String s) {
        return s != null && UUID.matcher(s).matches();
    }

    // ---- users --------------------------------------------------------------------------------------------------

    /** Resolves a user by id or username. */
    public UserRepresentation findUser(String realm, String idOrUsername) {
        RealmResource r = realm(realm);
        if (isUuid(idOrUsername)) {
            try {
                return r.users().get(idOrUsername).toRepresentation();
            } catch (NotFoundException e) {
                // fall through to username lookup
            }
        }
        List<UserRepresentation> byName = r.users().searchByUsername(idOrUsername, true);
        if (byName.size() == 1) {
            return byName.get(0);
        }
        if (byName.isEmpty() && idOrUsername != null && idOrUsername.contains("@")) {
            List<UserRepresentation> byEmail = r.users().searchByEmail(idOrUsername, true);
            if (byEmail.size() == 1) {
                return byEmail.get(0);
            }
        }
        throw ToolException.notFound("User", idOrUsername);
    }

    public UserResource user(String realm, String idOrUsername) {
        return realm(realm).users().get(findUser(realm, idOrUsername).getId());
    }

    // ---- clients ------------------------------------------------------------------------------------------------

    /** Resolves a client by internal id or clientId. */
    public ClientRepresentation findClient(String realm, String idOrClientId) {
        RealmResource r = realm(realm);
        if (isUuid(idOrClientId)) {
            try {
                return r.clients().get(idOrClientId).toRepresentation();
            } catch (NotFoundException e) {
                // fall through
            }
        }
        List<ClientRepresentation> found = r.clients().findByClientId(idOrClientId);
        if (found.size() == 1) {
            return found.get(0);
        }
        throw ToolException.notFound("Client", idOrClientId);
    }

    public ClientResource clientResource(String realm, String idOrClientId) {
        return realm(realm).clients().get(findClient(realm, idOrClientId).getId());
    }

    // ---- groups -------------------------------------------------------------------------------------------------

    /** Resolves a group by id, full path ({@code /parent/child}) or unique name. */
    public GroupRepresentation findGroup(String realm, String idOrPathOrName) {
        RealmResource r = realm(realm);
        if (isUuid(idOrPathOrName)) {
            try {
                return r.groups().group(idOrPathOrName).toRepresentation();
            } catch (NotFoundException e) {
                // fall through
            }
        }
        if (idOrPathOrName != null && idOrPathOrName.startsWith("/")) {
            try {
                return r.getGroupByPath(idOrPathOrName);
            } catch (NotFoundException e) {
                throw ToolException.notFound("Group", idOrPathOrName);
            }
        }
        // search returns the top-level ancestors with matching subgroups nested underneath: flatten first
        List<GroupRepresentation> found = new java.util.ArrayList<>();
        flatten(r.groups().groups(idOrPathOrName, true, 0, 20, false), found);
        List<GroupRepresentation> exact = found.stream().filter(g -> idOrPathOrName.equals(g.getName())).toList();
        if (exact.size() == 1) {
            return exact.get(0);
        }
        if (exact.size() > 1) {
            throw new ToolException("ambiguous", "Several groups are named '" + idOrPathOrName
                    + "'; pass the group id or full path instead.");
        }
        throw ToolException.notFound("Group", idOrPathOrName);
    }

    private static void flatten(List<GroupRepresentation> groups, List<GroupRepresentation> out) {
        if (groups == null) {
            return;
        }
        for (GroupRepresentation g : groups) {
            out.add(g);
            flatten(g.getSubGroups(), out);
        }
    }

    public GroupResource group(String realm, String idOrPathOrName) {
        return realm(realm).groups().group(findGroup(realm, idOrPathOrName).getId());
    }

    // ---- misc ---------------------------------------------------------------------------------------------------

    /** Extracts the id from a 201 response or turns an error response into a {@link ToolException}. */
    public static String created(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
            return CreatedResponseUtil.getCreatedId(response);
        }
    }

    /** Checks a plain response (204/200 expected) and closes it. */
    public static void ok(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
        }
    }

    public void close() {
        purgeDelegates(Long.MAX_VALUE, true);
        Keycloak k = keycloak;
        if (k != null) {
            try {
                k.close();
            } catch (RuntimeException e) {
                LOG.debug("Closing admin client failed", e);
            }
        }
        if (jwtTokens != null) {
            jwtTokens.close();
        }
    }
}
