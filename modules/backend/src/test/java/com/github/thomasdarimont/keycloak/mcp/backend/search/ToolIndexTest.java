package com.github.thomasdarimont.keycloak.mcp.backend.search;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ToolIndexTest {

    private final ToolIndex index = new ToolIndex(Fixtures.catalog(null).all());

    @ParameterizedTest
    @CsvSource({ "keycloak_user_search, keycloak_user_search", "user_serach, keycloak_user_search",
            "find user by email, keycloak_user_search", "disable user bob, keycloak_user_set_enabled",
            "block user, keycloak_user_set_enabled", "remove a user permanently, keycloak_user_delete",
            "ldap, keycloak_federation_sync", "active directory sync, keycloak_federation_sync",
            "which keycloak version, keycloak_server_info", "list users, keycloak_user_search",
            "search for a user, keycloak_user_search", "Benutzer deaktivieren, keycloak_user_set_enabled",
            "Benutzer löschen, keycloak_user_delete", "Nutzer suchen, keycloak_user_search",
            "LDAP Verzeichnis abgleichen, keycloak_federation_sync", })
    void topHit(String query, String expected) {
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.get(0).spec().name(), query + " -> " + hits);
    }

    @Test
    void possessivesAndSingleLettersDoNotMatchAnything() {
        assertEquals(List.of("tomorrow", "weather"), Tokenizer.tokens("tomorrow's weather please"));
        assertTrue(index.search("tomorrow's weather please", null, 5, s -> true).isEmpty(), "no stray 's' hits");
        assertEquals("keycloak_user_search",
                index.search("the user's account", null, 5, s -> true).get(0).spec().name(),
                "the possessive is dropped, the rest still matches");
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
        // name abbreviations are added next to the spelled out phrase
        assertEquals(List.of("find", "identity", "provider", "idp"), Tokenizer.tokens("list identity providers"));
    }

    @Test
    void foldsUmlautsAndAccents() {
        assertEquals("identitaetsanbieter loeschen", Tokenizer.fold("Identitätsanbieter löschen"));
        assertEquals("strasse jose", Tokenizer.fold("Straße José"));
        // an umlaut must not split the word
        assertEquals(List.of("identity", "provider", "delet", "idp"), Tokenizer.tokens("Identitätsanbieter löschen"));
    }

    @Test
    void translatesGermanQueryTerms() {
        assertEquals(List.of("user", "logout"), Tokenizer.tokens("Benutzer abmelden"));
        assertEquals(List.of("user", "logout"), Tokenizer.tokens("bitte alle Benutzer ausloggen"));
        assertEquals(List.of("group", "role"), Tokenizer.tokens("Gruppen und Rollen"));
        assertEquals(List.of("user", "disabl"), Tokenizer.tokens("Benutzern deaktivieren"));
        assertEquals(List.of("password", "reset"), Tokenizer.tokens("Passwort zurücksetzen"));
        // unknown words pass through unchanged, English is untouched
        assertEquals(List.of("foobar", "user"), Tokenizer.tokens("foobar users"));
    }

    @Test
    void negationIsNotASafetyMechanismOfTheSearch() {
        // "Benutzer nicht löschen, nur deaktivieren": the conversation is about deleting,
        // so the
        // delete tool belongs in the hits next to the disable tool; the level, the policy
        // and
        // the confirmation decide what runs, the search only finds (see the 2026-11-06
        // review)
        List<String> hits = index.search("Benutzer nicht löschen, nur deaktivieren", null, 5, s -> true)
            .stream()
            .map(h -> h.spec().name())
            .toList();
        assertTrue(hits.contains("keycloak_user_delete"), hits.toString());
        assertTrue(hits.contains("keycloak_user_set_enabled"), hits.toString());
    }
}
