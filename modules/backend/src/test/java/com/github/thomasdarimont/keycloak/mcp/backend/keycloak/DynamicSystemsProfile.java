package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.file.Path;
import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * The static default system plus the runtime repository
 * {@link TestKeycloakSystemRepository}.
 */
public class DynamicSystemsProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        // the file vault is read-only: the lab system's key is provisioned up front
        TestKeys.writePem(Path.of("target/test-keys/dynamic/lab.pem"), TestKeys.rsa().getPrivate());
        return Map.of("kc-mcp.dynamic-systems", "true", "kc-mcp.keys-dir", "target/test-keys/dynamic",
                "kc-mcp.startup-check", "off");
    }
}
