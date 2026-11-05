package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileSystemKeycloakSystemRepositoryTest {

    @Test
    void readsSystemsAndReloadsOnChange(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("systems.json");
        Files.writeString(file, """
                {"systems": [
                  {"name": "tenant-a", "url": "http://keycloak:8080", "authRealm": "tenant-a",
                   "issuer": "https://sso.example.com/realms/tenant-a",
                   "defaultRealm": "tenant-a", "allowedRealms": ["tenant-a", "shared"], "version": "26.8.1"},
                  {"name": "legacy", "url": "https://old.example.com", "grantType": "password",
                   "clientAuth": "none", "clientId": "admin-cli", "username": "admin", "password": "admin"}
                ]}
                """);
        FileSystemKeycloakSystemRepository source = new FileSystemKeycloakSystemRepository(file);
        assertEquals(List.of("tenant-a", "legacy"), source.names());
        KeycloakSystem a = source.find("tenant-a").orElseThrow();
        assertEquals(ClientAuth.PRIVATE_KEY_JWT, a.clientAuth(), "the default for tenants");
        assertEquals(GrantType.CLIENT_CREDENTIALS, a.grantType());
        assertEquals(Optional.of(FileSystemKeycloakSystemRepository.DEFAULT_CLIENT_ID), a.clientId());
        assertEquals("tenant-a", a.authRealm());
        assertEquals(Set.of("tenant-a", "shared"), a.allowedRealms());
        assertEquals(Optional.of("26.8.1"), a.version());
        assertEquals("https://sso.example.com/realms/tenant-a", a.assertionAudience(), "the public issuer");
        assertEquals("https://sso.example.com", a.publicUrl(), "where browsers reach it");
        assertEquals("https://old.example.com", source.find("legacy").orElseThrow().publicUrl());
        assertEquals("https://old.example.com/realms/master", source.find("legacy").orElseThrow().assertionAudience(),
                "derived from the URL without an issuer");
        KeycloakSystem legacy = source.find("legacy").orElseThrow();
        assertEquals(GrantType.PASSWORD, legacy.grantType());
        assertEquals(ClientAuth.NONE, legacy.clientAuth());
        assertEquals(Optional.of("admin"), legacy.username());
        assertTrue(source.find("nope").isEmpty());

        Files.writeString(file, "{\"systems\": [{\"name\": \"tenant-b\", \"url\": \"https://b.example.com\"}]}");
        Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 5000));
        assertEquals(List.of("tenant-b"), source.names(), "re-read after the file changed");

        assertTrue(new FileSystemKeycloakSystemRepository((Path) null).names().isEmpty());
        assertTrue(new FileSystemKeycloakSystemRepository(dir.resolve("missing.json")).names().isEmpty());
        assertThrows(IllegalArgumentException.class,
                () -> FileSystemKeycloakSystemRepository.parse(new JsonObject("{\"systems\": [{\"name\": \"x\"}]}")));
    }
}
