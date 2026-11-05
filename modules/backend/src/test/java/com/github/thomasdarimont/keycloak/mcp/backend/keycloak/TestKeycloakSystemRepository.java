package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.google.auto.service.AutoService;

/**
 * A runtime repository with one system, {@code lab}, authenticating with
 * {@code private_key_jwt}; repositories are off in the baseline test configuration
 * ({@code kc-mcp.dynamic-systems=false}) and on in {@link DynamicSystemsProfile}.
 */
@AutoService(KeycloakSystemRepository.class)
public class TestKeycloakSystemRepository implements KeycloakSystemRepository {

    public static final KeycloakSystem LAB = new KeycloakSystem("lab", "http://127.0.0.1:1",
            GrantType.CLIENT_CREDENTIALS, ClientAuth.PRIVATE_KEY_JWT, "master", Optional.of("keycloak-mcp-server"),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.of("tenant"), Set.of(), Optional.empty());

    @Override
    public String id() {
        return "test-systems";
    }

    @Override
    public List<String> names() {
        return List.of(LAB.name());
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        return LAB.name().equals(name) ? Optional.of(LAB) : Optional.empty();
    }
}
