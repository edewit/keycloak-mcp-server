package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.keycloak.CompositeKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompositeKeycloakSystemRepositoryTest {

    @Test
    void unionInOrderFirstRepositoryWinsAndFailuresAreSkipped() {
        InMemoryKeycloakSystemRepository first = new InMemoryKeycloakSystemRepository("first",
                List.of(DynamicSystemsTest.system("shared", "https://first.example.com"),
                        DynamicSystemsTest.system("only-first", "https://first.example.com")));
        InMemoryKeycloakSystemRepository second = new InMemoryKeycloakSystemRepository("second", 5,
                List.of(DynamicSystemsTest.system("shared", "https://second.example.com"),
                        DynamicSystemsTest.system("only-second", "https://second.example.com")));
        KeycloakSystemRepository broken = new KeycloakSystemRepository() {
            @Override
            public String id() {
                return "broken";
            }

            @Override
            public List<String> names() {
                throw new IllegalStateException("registry down");
            }

            @Override
            public Optional<KeycloakSystem> find(String name) {
                throw new IllegalStateException("registry down");
            }
        };
        List<String> failures = new ArrayList<>();
        CompositeKeycloakSystemRepository composite = new CompositeKeycloakSystemRepository(
                List.of(second, first, broken), (r, e) -> failures.add(r.id() + ": " + e.getMessage()));

        // ordered by order() then id, not by the list given: broken (0) and first (0)
        // before second (5)
        assertEquals(List.of("broken", "first", "second"),
                composite.repositories().stream().map(KeycloakSystemRepository::id).toList());
        assertEquals(List.of("shared", "only-first", "only-second"), composite.names());
        assertEquals("https://first.example.com", composite.find("shared").orElseThrow().url(), "first wins");
        assertEquals("https://second.example.com", composite.find("only-second").orElseThrow().url());
        assertTrue(composite.find("nope").isEmpty());
        assertEquals(3, composite.all().size());
        assertEquals("first", composite.repository(InMemoryKeycloakSystemRepository.class).orElseThrow().id());
        assertTrue(failures.stream().allMatch(f -> f.startsWith("broken: registry down")), failures.toString());
        assertTrue(failures.size() >= 3, "names, find(shared) and find(only-second) each reported: " + failures);

        // in-memory repository keeps insertion order, replaces in place, forgets on
        // remove
        first.put(DynamicSystemsTest.system("shared", "https://first2.example.com"));
        assertEquals(List.of("shared", "only-first"), first.names());
        assertEquals("https://first2.example.com", first.find("shared").orElseThrow().url());
        first.remove("shared");
        assertEquals("https://second.example.com", composite.find("shared").orElseThrow().url(),
                "falls through to the next repository");

        // a lower order puts a repository ahead of the others
        InMemoryKeycloakSystemRepository override = new InMemoryKeycloakSystemRepository("override", -1,
                List.of(DynamicSystemsTest.system("only-second", "https://override.example.com")));
        CompositeKeycloakSystemRepository ranked = new CompositeKeycloakSystemRepository(List.of(second, override));
        assertEquals("https://override.example.com", ranked.find("only-second").orElseThrow().url());
        assertEquals(List.of("only-second", "shared"), ranked.names());
    }
}
