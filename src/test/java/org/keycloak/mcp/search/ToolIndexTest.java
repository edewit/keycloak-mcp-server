package org.keycloak.mcp.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.mcp.Fixtures;
import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolSpec;

class ToolIndexTest {

    private final ToolIndex index = new ToolIndex(Fixtures.catalog(null).all());

    @ParameterizedTest
    @CsvSource({
            "keycloak_user_search, keycloak_user_search",
            "user_serach, keycloak_user_search",
            "find user by email, keycloak_user_search",
            "disable user bob, keycloak_user_set_enabled",
            "block user, keycloak_user_set_enabled",
            "remove a user permanently, keycloak_user_delete",
            "ldap, keycloak_federation_sync",
            "active directory sync, keycloak_federation_sync",
            "which keycloak version, keycloak_server_info",
    })
    void topHit(String query, String expected) {
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.get(0).spec().name(), query + " -> " + hits);
    }

    @Test
    void readBeatsWriteOnTie() {
        List<SearchHit> hits = index.search("user", null, 5, s -> true);
        assertEquals("keycloak_user_search", hits.get(0).spec().name());
        assertEquals("keycloak_user_set_enabled", hits.get(1).spec().name());
        assertEquals("keycloak_user_delete", hits.get(2).spec().name());
    }

    @Test
    void categoryIsAHardFilter() {
        List<SearchHit> hits = index.search("user", Category.FEDERATION, 5, s -> true);
        assertEquals(List.of("keycloak_federation_sync"), hits.stream().map(h -> h.spec().name()).toList());
        // empty query + category lists the category
        assertEquals(3, index.search("", Category.USERS, 5, s -> true).size());
    }

    @Test
    void visibilityPredicateHidesTools() {
        List<SearchHit> hits = index.search("user", null, 5, ToolSpec::isReadOnly);
        assertEquals(List.of("keycloak_user_search"), hits.stream().map(h -> h.spec().name()).toList());
    }

    @Test
    void limitIsHonoured() {
        assertEquals(2, index.search("user", null, 2, s -> true).size());
    }

    @Test
    void similarNamesForTypos() {
        List<SearchHit> hits = index.similarNames("keycloak_user_delte", 3, s -> true);
        assertEquals("keycloak_user_delete", hits.get(0).spec().name());
    }

    @Test
    void fuzzyDistance() {
        assertEquals(0, Fuzzy.distance("abc", "abc"));
        assertEquals(1, Fuzzy.distance("serach", "search"));
        assertEquals(1, Fuzzy.distance("delte", "delete"));
        assertEquals(3, Fuzzy.distance("abc", "abcdef", 2));
    }

    @Test
    void tokenizer() {
        assertEquals(List.of("user", "disabl", "group"), Tokenizer.tokens("the users: disabled, Groups"));
        assertEquals(List.of("redirect", "uri"), Tokenizer.tokens("redirectUris"));
    }
}
