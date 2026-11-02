package org.keycloak.mcp.keycloak;

import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
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
import org.keycloak.mcp.config.McpServerConfig;
import org.keycloak.mcp.guard.ErrorMapper;
import org.keycloak.mcp.guard.ToolException;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Lazily built Keycloak admin client plus the lookup helpers every tool area needs. Identifier arguments are
 * forgiving: a user may be given by id or username, a client by id or clientId, a group by id, path or name.
 */
@ApplicationScoped
public class KeycloakAdmin {

    private static final Logger LOG = Logger.getLogger(KeycloakAdmin.class);
    private static final Pattern UUID = Pattern
            .compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private final McpServerConfig config;
    private final ReentrantLock initLock = new ReentrantLock();
    private volatile Keycloak keycloak;
    private volatile ClientAssertionTokenManager jwtTokens;

    @Inject
    public KeycloakAdmin(McpServerConfig config) {
        this.config = config;
        ErrorMapper.register(KeycloakErrors::map);
    }

    public McpServerConfig config() {
        return config;
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
        GrantType grant = config.grantType();
        ClientAuth auth = config.effectiveClientAuth();
        LOG.infof("Connecting to Keycloak at %s (grant=%s, clientAuth=%s, authRealm=%s)", config.url(),
                grant.oauthValue(), auth, config.authRealm());
        if (grant == GrantType.CLIENT_CREDENTIALS && auth == ClientAuth.NONE) {
            throw new IllegalStateException("Missing configuration: the client_credentials grant needs "
                    + "'kc-mcp.client-secret' or a private_key_jwt key ('kc-mcp.jwt.key-file' / 'kc-mcp.jwt.keystore-file')");
        }
        String clientId = config.clientId().filter(v -> !v.isBlank())
                .orElseGet(() -> grant == GrantType.PASSWORD && auth == ClientAuth.NONE ? "admin-cli" : null);
        if (clientId == null) {
            throw new IllegalStateException("Missing configuration 'kc-mcp.client-id'");
        }
        String username = grant == GrantType.PASSWORD ? require(config.username(), "kc-mcp.username") : null;
        String password = grant == GrantType.PASSWORD ? require(config.password(), "kc-mcp.password") : null;

        KeycloakBuilder builder = KeycloakBuilder.builder()
                .serverUrl(config.url())
                .realm(config.authRealm())
                .clientId(clientId);
        switch (auth) {
            case NONE -> builder.grantType(grant.oauthValue()).username(username).password(password);
            case CLIENT_SECRET -> builder.grantType(grant.oauthValue()).username(username).password(password)
                    .clientSecret(require(config.clientSecret(), "kc-mcp.client-secret"));
            case PRIVATE_KEY_JWT -> {
                Client restClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                Client tokenClient = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
                jwtTokens = new ClientAssertionTokenManager(tokenClient, config.url(), config.authRealm(), clientId,
                        JwtSigner.fromConfig(config.jwt()), config.jwt().assertionLifespan(), grant, username, password);
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

    @PreDestroy
    void close() {
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
