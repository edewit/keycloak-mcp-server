package org.keycloak.mcp.server.policies;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The few directory questions the built-in policy checks ask. Role keys use the
 * {@code RoleRef} syntax: {@code realm:<role>} and {@code <clientId>.<role>}. Implemented
 * against the admin client by {@link KeycloakDirectory}; tests use an in-memory fake.
 */
public interface RealmDirectory {

    /** User id in {@code realm} for a caller subject (user id) or username. */
    Optional<String> userId(String realm, String subjectOrUsername);

    /** Effective roles of a user: direct, group-inherited and composite-expanded. */
    Set<String> effectiveRoles(String realm, String userId);

    /**
     * A role plus everything it grants through composites; empty if the role does not
     * exist.
     */
    Set<String> roleClosure(String realm, String roleKey);

    /** Paths of the groups a user is a direct member of. */
    List<String> groupPaths(String realm, String userId);

    /** Full path of a group given by id, path or unique name. */
    Optional<String> groupPath(String realm, String groupRef);

    /**
     * Roles a member of the group gets: the group's and its ancestors' mappings,
     * composite-expanded.
     */
    Set<String> groupRoles(String realm, String groupPath);

    /** Organizations a user is a member of. */
    Set<String> organizationsOfUser(String realm, String userId);

    /** Organizations a group belongs to. */
    Set<String> organizationsOfGroup(String realm, String groupPath);
}
