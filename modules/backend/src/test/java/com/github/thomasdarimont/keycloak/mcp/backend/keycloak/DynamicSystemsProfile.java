package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * The static default system plus the runtime repository
 * {@link TestKeycloakSystemRepository}.
 */
public class DynamicSystemsProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of("kc-mcp.dynamic-systems", "true", "kc-mcp.keys-dir", "target/test-keys/dynamic",
                "kc-mcp.startup-check", "off");
    }
}
