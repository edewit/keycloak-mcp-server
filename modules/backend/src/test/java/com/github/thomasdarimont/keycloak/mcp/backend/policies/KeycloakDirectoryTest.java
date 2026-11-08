package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.GroupRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;

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
}
