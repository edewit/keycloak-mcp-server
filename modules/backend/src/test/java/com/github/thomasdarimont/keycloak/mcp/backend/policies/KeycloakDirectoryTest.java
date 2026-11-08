package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeycloakDirectoryTest {

    /**
     * A user in {@code n} groups, the last one {@code /administrators}, served in pages.
     */
    private static KeycloakDirectory.GroupPager memberOf(int n, List<Integer> pagesAsked) {
        List<GroupRepresentation> groups = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            GroupRepresentation g = new GroupRepresentation();
            g.setPath(i == n ? "/administrators" : "/team-" + i);
            groups.add(g);
        }
        return (first, max) -> {
            pagesAsked.add(first);
            return groups.subList(Math.min(first, n), Math.min(first + max, n));
        };
    }

    @Test
    void everyMembershipIsReadNotJustTheFirstPage() {
        List<Integer> pagesAsked = new ArrayList<>();
        List<GroupRepresentation> all = KeycloakDirectory.allGroups(memberOf(501, pagesAsked));

        assertEquals(501, all.size());
        assertEquals("/administrators", all.get(500).getPath(), "the membership on the second page is seen");
        assertEquals(List.of(0, 500), pagesAsked);
    }

    @Test
    void aFullLastPageIsFollowedByOneMoreRequest() {
        List<Integer> pagesAsked = new ArrayList<>();
        assertEquals(500, KeycloakDirectory.allGroups(memberOf(500, pagesAsked)).size());
        assertEquals(List.of(0, 500), pagesAsked, "only an empty page proves the listing ended");

        pagesAsked.clear();
        assertEquals(3, KeycloakDirectory.allGroups(memberOf(3, pagesAsked)).size());
        assertEquals(List.of(0), pagesAsked);
    }

    @Test
    void aListingThatNeverEndsFailsTheLookup() {
        KeycloakDirectory.GroupPager endless = (first, max) -> IntStream.range(0, max).mapToObj(i -> {
            GroupRepresentation g = new GroupRepresentation();
            g.setPath("/g-" + (first + i));
            return g;
        }).toList();

        ToolException e = assertThrows(ToolException.class, () -> KeycloakDirectory.allGroups(endless));
        assertEquals("groups_unreadable", e.code());
    }

    /**
     * The admin client as a tree of proxies answering the few calls the directory makes,
     * counting each: u1 is in {@code /a/b} and {@code /a/c}; {@code /a} maps the
     * composite realm role admin (granting x), {@code /a/b} the client role
     * realm-management manage-users, {@code /a/c} nothing.
     */
    static final class FakeAdmin {
        final Map<String, Integer> calls = new TreeMap<>();
        final Map<String, MappingsRepresentation> mappingsOfGroup = new HashMap<>();
        final Map<String, Set<RoleRepresentation>> compositesOfRole = new HashMap<>();
        final List<GroupRepresentation> groupsOfU1 = List.of(group("/a/b"), group("/a/c"));

        FakeAdmin() {
            RoleRepresentation admin = realmRole("admin-id", "admin", true);
            RoleRepresentation x = realmRole("x-id", "x", false);
            RoleRepresentation manageUsers = new RoleRepresentation();
            manageUsers.setId("mu-id");
            manageUsers.setName("manage-users");
            manageUsers.setClientRole(true);
            manageUsers.setContainerId("rm-uuid");
            MappingsRepresentation a = new MappingsRepresentation();
            a.setRealmMappings(List.of(admin));
            mappingsOfGroup.put("/a", a);
            ClientMappingsRepresentation cm = new ClientMappingsRepresentation();
            cm.setMappings(List.of(manageUsers));
            MappingsRepresentation b = new MappingsRepresentation();
            b.setClientMappings(Map.of("realm-management", cm));
            mappingsOfGroup.put("/a/b", b);
            compositesOfRole.put("admin-id", Set.of(x));
        }

        static GroupRepresentation group(String path) {
            GroupRepresentation g = new GroupRepresentation();
            g.setId(path);
            g.setPath(path);
            return g;
        }

        static RoleRepresentation realmRole(String id, String name, boolean composite) {
            RoleRepresentation r = new RoleRepresentation();
            r.setId(id);
            r.setName(name);
            r.setComposite(composite);
            return r;
        }

        KeycloakAdmin admin() {
            return proxy(KeycloakAdmin.class, Map.of());
        }

        int calls(String what) {
            return calls.getOrDefault(what, 0);
        }

        private void count(String what) {
            calls.merge(what, 1, Integer::sum);
        }

        /** @param captured the string arguments along the chain, by method name */
        private <T> T proxy(Class<T> type, Map<String, String> captured) {
            InvocationHandler h = (proxy, m, args) -> {
                String name = m.getName();
                Map<String, String> next = new HashMap<>(captured);
                if (args != null && args.length == 1 && args[0] instanceof String s) {
                    next.put(name, s);
                }
                switch (name) {
                    case "isDelegated" -> {
                        return false;
                    }
                    case "getGroupByPath" -> {
                        count("group " + args[0]);
                        return group((String) args[0]);
                    }
                    case "groups" -> {
                        if (args != null && args.length == 3) {
                            count("memberships " + captured.get("get"));
                            return "u1".equals(captured.get("get")) ? groupsOfU1 : List.of();
                        }
                    }
                    case "listEffective" -> {
                        count("effective " + captured.get("get"));
                        return List.of();
                    }
                    case "getAll" -> {
                        if (captured.containsKey("group")) {
                            count("mappings " + captured.get("group"));
                            return mappingsOfGroup.getOrDefault(captured.get("group"), new MappingsRepresentation());
                        }
                        count("direct " + captured.get("get"));
                        return new MappingsRepresentation();
                    }
                    case "getRoleComposites" -> {
                        count("composites " + args[0]);
                        return compositesOfRole.getOrDefault((String) args[0], Set.of());
                    }
                    case "toRepresentation" -> {
                        count("client " + captured.get("get"));
                        ClientRepresentation c = new ClientRepresentation();
                        c.setClientId("rm-uuid".equals(captured.get("get")) ? "realm-management" : "?");
                        return c;
                    }
                    case "toString" -> {
                        return "fake " + type.getSimpleName();
                    }
                    case "hashCode" -> {
                        return System.identityHashCode(proxy);
                    }
                    case "equals" -> {
                        return proxy == args[0];
                    }
                    default -> {
                    }
                }
                if (m.getReturnType().isInterface()) {
                    return proxy(m.getReturnType(), next);
                }
                if (m.isDefault()) {
                    return InvocationHandler.invokeDefault(proxy, m, args);
                }
                throw new UnsupportedOperationException(name);
            };
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, h));
        }
    }

    @Test
    void oneEvaluationReadsEachGroupAndRoleOnce() {
        FakeAdmin fake = new FakeAdmin();
        KeycloakDirectory directory = new KeycloakDirectory(fake.admin());

        assertEquals(Set.of("realm:admin", "realm:x", "realm-management.manage-users"),
                directory.effectiveRoles("demo", "u1"));
        assertEquals(1, fake.calls("group /a"), "the shared ancestor of /a/b and /a/c is read once");
        assertEquals(1, fake.calls("mappings /a"));
        assertEquals(1, fake.calls("composites admin-id"));
        assertEquals(1, fake.calls("client rm-uuid"));

        Map<String, Integer> before = new TreeMap<>(fake.calls);
        assertEquals(Set.of("realm:admin", "realm:x", "realm-management.manage-users"),
                directory.groupRoles("demo", "/a/b"));
        assertEquals(List.of("/a/b", "/a/c"), directory.groupPaths("demo", "u1"));
        assertEquals(before, fake.calls, "later questions of the same evaluation are answered from memory");
    }

    @Test
    void theNextEvaluationReadsAgainButKeepsTheClientIds() {
        FakeAdmin fake = new FakeAdmin();
        Map<String, String> clientIds = new ConcurrentHashMap<>();
        new KeycloakDirectory(fake.admin(), clientIds).groupRoles("demo", "/a/b");
        new KeycloakDirectory(fake.admin(), clientIds).groupRoles("demo", "/a/b");

        assertEquals(2, fake.calls("mappings /a/b"), "mappings may have changed between calls");
        assertEquals(1, fake.calls("client rm-uuid"), "a client's id does not");
    }
}
