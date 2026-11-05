package com.github.thomasdarimont.keycloak.mcp.server.policies;

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
        for (GroupRepresentation g : u.groups(0, 500, true)) {
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
        return kc.realm(realm)
            .users()
            .get(userId)
            .groups(0, 500, true)
            .stream()
            .map(GroupRepresentation::getPath)
            .toList();
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
                // unreadable ancestor: skip
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
                    // composites unreadable: keep what we have
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
