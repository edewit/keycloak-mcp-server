package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamicSystemsTest {

    /** A source backed by a map the test edits. */
    static final class MapSource implements KeycloakSystemSource {
        final Map<String, KeycloakSystem> systems = new LinkedHashMap<>();

        @Override
        public String id() {
            return "map";
        }

        @Override
        public List<String> names() {
            return List.copyOf(systems.keySet());
        }

        @Override
        public Optional<KeycloakSystem> find(String name) {
            return Optional.ofNullable(systems.get(name));
        }
    }

    static KeycloakSystem system(String name, String url) {
        return new KeycloakSystem(name, url, GrantType.CLIENT_CREDENTIALS, ClientAuth.NONE, "master", Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Set.of(), Optional.empty());
    }

    @Test
    void sourcesAddSystemsNextToTheStaticOnes() {
        MapSource source = new MapSource();
        source.systems.put("tenant-a", system("tenant-a", "https://a.example.com"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(system("hub", "https://hub.example.com")),
                null, null, HostAllowList.ANY, List.of(source));
        try {
            assertTrue(systems.dynamic());
            assertTrue(systems.multiple());
            assertEquals(List.of("hub", "tenant-a"), systems.names());
            assertTrue(systems.defaultName().isEmpty(), "one static system plus a source is not a single system");

            KeycloakAdmin a = systems.get("tenant-a");
            assertSame(a, systems.get("tenant-a"), "cached");
            assertEquals("https://a.example.com", a.system().url());
            assertTrue(systems.find("tenant-b").isEmpty());
            assertThrows(IllegalArgumentException.class, () -> systems.get("tenant-b"));

            // the source learns a system, changes one, forgets one
            source.systems.put("tenant-b", system("tenant-b", "https://b.example.com"));
            assertEquals(List.of("hub", "tenant-a", "tenant-b"), systems.names());
            assertTrue(systems.find("tenant-b").isPresent());
            source.systems.put("tenant-a", system("tenant-a", "https://a2.example.com"));
            KeycloakAdmin a2 = systems.get("tenant-a");
            assertNotSame(a, a2, "reconnected after the settings changed");
            assertEquals("https://a2.example.com", a2.system().url());
            source.systems.remove("tenant-a");
            assertTrue(systems.find("tenant-a").isEmpty());
            assertEquals(2, systems.all().size());
        }
        finally {
            systems.close();
        }
    }

    @Test
    void dynamicSystemsOutsideTheAllowListAreRefusedNotFatal() {
        MapSource source = new MapSource();
        source.systems.put("inside", system("inside", "https://ok.example.com"));
        source.systems.put("outside", system("outside", "https://kc.evil.test"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(), null, null,
                HostAllowList.of(List.of("*.example.com")), List.of(source));
        try {
            assertTrue(systems.find("inside").isPresent());
            assertTrue(systems.find("outside").isEmpty());
            assertEquals(List.of("inside", "outside"), systems.names(), "listed, but not connectable");
        }
        finally {
            systems.close();
        }
    }

    @Test
    void aSourceAloneIsEnoughAndTheDefaultMayComeFromIt() {
        MapSource source = new MapSource();
        source.systems.put("main", system("main", "https://main.example.com"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(), "main", null, HostAllowList.ANY,
                List.of(source));
        try {
            assertEquals(Optional.of("main"), systems.defaultName());
            assertEquals("main", systems.defaultAdmin().name());
        }
        finally {
            systems.close();
        }
        assertThrows(IllegalStateException.class,
                () -> new DefaultKeycloakSystems(List.of(), "other", null, HostAllowList.ANY, List.of(source)));
        assertThrows(IllegalStateException.class,
                () -> new DefaultKeycloakSystems(List.of(), null, null, HostAllowList.ANY, List.of()));
        assertFalse(new DefaultKeycloakSystems(List.of(system("only", "http://x")), null, null).dynamic());
    }
}
