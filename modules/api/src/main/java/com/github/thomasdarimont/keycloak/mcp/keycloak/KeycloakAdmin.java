package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;

/**
 * The Keycloak admin client a tool handler works with ({@code ToolCall.kc()}): the
 * connection to one {@link KeycloakSystem} plus the lookup helpers every tool area needs.
 * Identifier arguments are forgiving: a user may be given by id, username or email, a
 * client by id or clientId, a group by id, path or name. The server implements it once
 * per configured system and once more per caller token in delegation mode
 * {@code forward}.
 */
public interface KeycloakAdmin extends AccessTokenSource {

    Pattern UUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /** The system this client talks to. */
    KeycloakSystem system();

    /** The system's name. */
    String name();

    /** The underlying admin client (built and logged in on first use). */
    Keycloak client();

    /**
     * An admin client of the same system that sends the given caller token instead of the
     * server's credentials (delegation mode {@code forward}).
     */
    KeycloakAdmin forToken(String bearerToken);

    /**
     * Whether this instance forwards a caller's token rather than using the server's
     * credentials.
     */
    boolean isDelegated();

    /** Scope evaluation endpoints (no admin client binding exists). */
    ScopeEvaluation scopeEvaluation();

    void close();

    default RealmResource realm(String realm) {
        return client().realm(realm);
    }

    static boolean isUuid(String s) {
        return s != null && UUID.matcher(s).matches();
    }

    // ---- users -----------------------------------------------------------------------

    /** Resolves a user by id, username or (unique) email. */
    default UserRepresentation findUser(String realm, String idOrUsername) {
        RealmResource r = realm(realm);
        if (isUuid(idOrUsername)) {
            try {
                return r.users().get(idOrUsername).toRepresentation();
            }
            catch (NotFoundException e) {
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

    default UserResource user(String realm, String idOrUsername) {
        return realm(realm).users().get(findUser(realm, idOrUsername).getId());
    }

    // ---- clients ---------------------------------------------------------------------

    /** Resolves a client by internal id or clientId. */
    default ClientRepresentation findClient(String realm, String idOrClientId) {
        RealmResource r = realm(realm);
        if (isUuid(idOrClientId)) {
            try {
                return r.clients().get(idOrClientId).toRepresentation();
            }
            catch (NotFoundException e) {
                // fall through
            }
        }
        List<ClientRepresentation> found = r.clients().findByClientId(idOrClientId);
        if (found.size() == 1) {
            return found.get(0);
        }
        throw ToolException.notFound("Client", idOrClientId);
    }

    default ClientResource clientResource(String realm, String idOrClientId) {
        return realm(realm).clients().get(findClient(realm, idOrClientId).getId());
    }

    // ---- groups ----------------------------------------------------------------------

    /** Resolves a group by id, full path ({@code /parent/child}) or unique name. */
    default GroupRepresentation findGroup(String realm, String idOrPathOrName) {
        RealmResource r = realm(realm);
        if (isUuid(idOrPathOrName)) {
            try {
                return r.groups().group(idOrPathOrName).toRepresentation();
            }
            catch (NotFoundException e) {
                // fall through
            }
        }
        if (idOrPathOrName != null && idOrPathOrName.startsWith("/")) {
            try {
                return r.getGroupByPath(idOrPathOrName);
            }
            catch (NotFoundException e) {
                throw ToolException.notFound("Group", idOrPathOrName);
            }
        }
        // search returns the top-level ancestors with matching subgroups nested
        // underneath: flatten first
        List<GroupRepresentation> found = new ArrayList<>();
        flattenGroups(r.groups().groups(idOrPathOrName, true, 0, 20, false), found);
        List<GroupRepresentation> exact = found.stream().filter(g -> idOrPathOrName.equals(g.getName())).toList();
        if (exact.size() == 1) {
            return exact.get(0);
        }
        if (exact.size() > 1) {
            throw new ToolException("ambiguous",
                    "Several groups are named '" + idOrPathOrName + "'; pass the group id or full path instead.");
        }
        throw ToolException.notFound("Group", idOrPathOrName);
    }

    private static void flattenGroups(List<GroupRepresentation> groups, List<GroupRepresentation> out) {
        if (groups == null) {
            return;
        }
        for (GroupRepresentation g : groups) {
            out.add(g);
            flattenGroups(g.getSubGroups(), out);
        }
    }

    default GroupResource group(String realm, String idOrPathOrName) {
        return realm(realm).groups().group(findGroup(realm, idOrPathOrName).getId());
    }

    // ---- responses -------------------------------------------------------------------

    /**
     * Extracts the id from a 201 response or turns an error response into a
     * {@link ToolException}.
     */
    static String created(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
            return CreatedResponseUtil.getCreatedId(response);
        }
    }

    /** Checks a plain response (204/200 expected) and closes it. */
    static void ok(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
        }
    }

}
