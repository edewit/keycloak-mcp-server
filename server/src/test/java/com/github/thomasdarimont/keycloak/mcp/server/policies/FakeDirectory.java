package com.github.thomasdarimont.keycloak.mcp.server.policies;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** In-memory directory for one realm. */
public class FakeDirectory implements RealmDirectory {

    final Map<String, String> usersByName = new HashMap<>();
    final Map<String, Set<String>> effective = new HashMap<>();
    final Map<String, Set<String>> closures = new HashMap<>();
    final Map<String, List<String>> userGroups = new HashMap<>();
    final Map<String, Set<String>> groupRoles = new HashMap<>();
    final Map<String, Set<String>> userOrgs = new HashMap<>();
    final Map<String, Set<String>> groupOrgs = new HashMap<>();

    FakeDirectory user(String name, Set<String> roles, List<String> groups, Set<String> orgs) {
        usersByName.put(name, "id-" + name);
        effective.put("id-" + name, roles);
        userGroups.put("id-" + name, groups);
        userOrgs.put("id-" + name, orgs);
        return this;
    }

    FakeDirectory role(String key, Set<String> closure) {
        closures.put(key, closure);
        return this;
    }

    FakeDirectory group(String path, Set<String> roles, Set<String> orgs) {
        groupRoles.put(path, roles);
        groupOrgs.put(path, orgs);
        return this;
    }

    @Override
    public Optional<String> userId(String realm, String subjectOrUsername) {
        if (usersByName.containsKey(subjectOrUsername)) {
            return Optional.of(usersByName.get(subjectOrUsername));
        }
        return usersByName.containsValue(subjectOrUsername) ? Optional.of(subjectOrUsername) : Optional.empty();
    }

    @Override
    public Set<String> effectiveRoles(String realm, String userId) {
        return effective.getOrDefault(userId, Set.of());
    }

    @Override
    public Set<String> roleClosure(String realm, String roleKey) {
        return closures.getOrDefault(roleKey, Set.of());
    }

    @Override
    public List<String> groupPaths(String realm, String userId) {
        return userGroups.getOrDefault(userId, List.of());
    }

    @Override
    public Optional<String> groupPath(String realm, String groupRef) {
        if (groupRoles.containsKey(groupRef)) {
            return Optional.of(groupRef);
        }
        return groupRoles.keySet().stream().filter(p -> p.endsWith("/" + groupRef)).findFirst();
    }

    @Override
    public Set<String> groupRoles(String realm, String groupPath) {
        return groupRoles.getOrDefault(groupPath, Set.of());
    }

    @Override
    public Set<String> organizationsOfUser(String realm, String userId) {
        return userOrgs.getOrDefault(userId, Set.of());
    }

    @Override
    public Set<String> organizationsOfGroup(String realm, String groupPath) {
        return groupOrgs.getOrDefault(groupPath, Set.of());
    }
}
