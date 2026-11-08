package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.RoleRef;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * {@link RealmDirectory} backed by the admin client. Effective roles = realm-level
 * effective roles (already group- and composite-expanded by Keycloak) + direct and
 * group-inherited client roles, with composites expanded through {@code roles-by-id}.
 */
public class KeycloakDirectory implements RealmDirectory {

    private final KeycloakAdmin kc;
    private final Map<String, String> clientIdByUuid = new ConcurrentHashMap<>();

    public KeycloakDirectory(KeycloakAdmin kc) {
        this.kc = kc;
    }

    @Override
    public Optional<String> userId(String realm, String subjectOrUsername) {
        if (subjectOrUsername == null || subjectOrUsername.isBlank()) {
            return Optional.empty();
        }
        try {
            UserRepresentation u = kc.findUser(realm, subjectOrUsername);
            return Optional.ofNullable(u.getId());
        }
        catch (ToolException | WebApplicationException e) {
            return Optional.empty();
        }
    }

    @Override
    public Set<String> effectiveRoles(String realm, String userId) {
        RealmResource r = kc.realm(realm);
        UserResource u = r.users().get(userId);
        List<RoleRepresentation> seeds = new ArrayList<>(u.roles().realmLevel().listEffective(false));
        addClientMappings(u.roles().getAll(), seeds);
        for (GroupRepresentation g : allGroups(u)) {
            seeds.addAll(groupChainMappings(realm, g.getPath()));
        }
        Set<String> out = new TreeSet<>();
        expand(realm, seeds, out, new HashSet<>());
        return out;
    }

    @Override
    public Set<String> roleClosure(String realm, String roleKey) {
        RoleRef ref = RoleRef.parse(roleKey);
        RoleRepresentation role;
        try {
            role = switch (ref.kind()) {
                case REALM -> kc.realm(realm).roles().get(ref.role()).toRepresentation();
                default -> kc.clientResource(realm, ref.client()).roles().get(ref.role()).toRepresentation();
            };
        }
        catch (NotFoundException | ToolException e) {
            return Set.of();
        }
        Set<String> out = new TreeSet<>();
        expand(realm, List.of(role), out, new HashSet<>());
        return out;
    }

    @Override
    public List<String> groupPaths(String realm, String userId) {
        return allGroups(kc.realm(realm).users().get(userId)).stream().map(GroupRepresentation::getPath).toList();
    }

    @Override
    public Optional<String> groupPath(String realm, String groupRef) {
        try {
            return Optional.ofNullable(kc.findGroup(realm, groupRef).getPath());
        }
        catch (ToolException | WebApplicationException e) {
            return Optional.empty();
        }
    }

    @Override
    public Set<String> groupRoles(String realm, String groupPath) {
        Set<String> out = new TreeSet<>();
        expand(realm, groupChainMappings(realm, groupPath), out, new HashSet<>());
        return out;
    }

    @Override
    public Set<String> organizationsOfUser(String realm, String userId) {
        try {
            Set<String> ids = new TreeSet<>();
            for (OrganizationRepresentation o : kc.realm(realm).organizations().members().getOrganizations(userId)) {
                ids.add(o.getId());
            }
            return ids;
        }
        catch (WebApplicationException e) {
            return Set.of();
        }
    }

    /**
     * Organization groups carry the organization id in the {@code kc.org} attribute (own
     * or inherited).
     */
    @Override
    public Set<String> organizationsOfGroup(String realm, String groupPath) {
        Set<String> ids = new TreeSet<>();
        for (String path : ancestorPaths(groupPath)) {
            try {
                GroupRepresentation g = kc.realm(realm).getGroupByPath(path);
                if (g.getAttributes() != null && g.getAttributes().get("kc.org") != null) {
                    ids.addAll(g.getAttributes().get("kc.org"));
                }
            }
            catch (WebApplicationException e) {
                // ignore unreadable ancestors
            }
        }
        return ids;
    }

    // ---- helpers
    // ------------------------------------------------------------------------------------------------

    static List<String> ancestorPaths(String path) {
        List<String> out = new ArrayList<>();
        String[] parts = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (p.isEmpty()) {
                continue;
            }
            sb.append('/').append(p);
            out.add(sb.toString());
        }
        return out;
    }

    /**
     * A page of a user's groups: {@code (first, max)} to the groups from {@code first}.
     */
    interface GroupPager {
        List<GroupRepresentation> page(int first, int max);
    }

    static final int GROUP_PAGE = 500;
    static final int MAX_GROUPS = 20_000;

    private static List<GroupRepresentation> allGroups(UserResource u) {
        return allGroups((first, max) -> u.groups(first, max, true));
    }

    /**
     * Every group of a user, read page by page until a short page ends the listing. A
     * single page would silently drop the memberships beyond it, and a membership the
     * policies do not see is one they cannot protect; a listing that does not end within
     * {@link #MAX_GROUPS} fails the lookup for the same reason.
     */
    static List<GroupRepresentation> allGroups(GroupPager pager) {
        List<GroupRepresentation> all = new ArrayList<>();
        for (int first = 0; first < MAX_GROUPS; first += GROUP_PAGE) {
            List<GroupRepresentation> page = pager.page(first, GROUP_PAGE);
            all.addAll(page);
            if (page.size() < GROUP_PAGE) {
                return all;
            }
        }
        throw new ToolException("groups_unreadable", "The user belongs to more than " + MAX_GROUPS
                + " groups, more than the policies can judge in one call.");
    }

    private List<RoleRepresentation> groupChainMappings(String realm, String path) {
        List<RoleRepresentation> out = new ArrayList<>();
        RealmResource r = kc.realm(realm);
        for (String p : ancestorPaths(path)) {
            try {
                GroupRepresentation g = r.getGroupByPath(p);
                MappingsRepresentation m = r.groups().group(g.getId()).roles().getAll();
                if (m.getRealmMappings() != null) {
                    out.addAll(m.getRealmMappings());
                }
                addClientMappings(m, out);
            }
            catch (WebApplicationException e) {
                // an unreadable group would make the chain look smaller than it is, and
                // the policies would then allow what they should not: fail the lookup
                throw new ToolException("group_unreadable",
                        "The role mappings of group '" + p + "' in realm '" + realm + "' could not be read (HTTP "
                                + e.getResponse().getStatus() + "), so the policies cannot judge" + " this call.");
            }
        }
        return out;
    }

    private static void addClientMappings(MappingsRepresentation m, List<RoleRepresentation> out) {
        if (m == null || m.getClientMappings() == null) {
            return;
        }
        for (ClientMappingsRepresentation cm : m.getClientMappings().values()) {
            if (cm.getMappings() != null) {
                out.addAll(cm.getMappings());
            }
        }
    }

    private void expand(String realm, List<RoleRepresentation> roles, Set<String> out, Set<String> visited) {
        for (RoleRepresentation role : roles) {
            if (role == null || role.getId() == null || !visited.add(role.getId())) {
                continue;
            }
            out.add(keyOf(realm, role));
            if (role.isComposite()) {
                try {
                    expand(realm, new ArrayList<>(kc.realm(realm).rolesById().getRoleComposites(role.getId())), out,
                            visited);
                }
                catch (WebApplicationException e) {
                    // the same for a composite: a role that looks smaller than it is
                    // would
                    // pass the escalation check
                    throw new ToolException("role_unreadable",
                            "The composites of role '" + role.getName() + "' in realm '" + realm
                                    + "' could not be read (HTTP " + e.getResponse().getStatus()
                                    + "), so the policies cannot judge this call.");
                }
            }
        }
    }

    private String keyOf(String realm, RoleRepresentation role) {
        if (Boolean.TRUE.equals(role.getClientRole())) {
            String clientId = clientIdByUuid.computeIfAbsent(role.getContainerId(), uuid -> {
                try {
                    return kc.realm(realm).clients().get(uuid).toRepresentation().getClientId();
                }
                catch (WebApplicationException e) {
                    return uuid;
                }
            });
            return clientId + "." + role.getName();
        }
        return "realm:" + role.getName();
    }
}
