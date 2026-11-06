package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * The storage module on an in-memory H2 database: only the datasource URL is set, the
 * storage switch follows from it.
 */
public class StorageProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-storage-test;DB_CLOSE_DELAY=-1",
                // the entities must match what Liquibase creates (dev mode validates
                // after boot)
                "quarkus.hibernate-orm.schema-management.strategy", "validate", "kc-mcp.storage.secret-key",
                "test-passphrase", "kc-mcp.dynamic-systems", "true", "kc-mcp.startup-check", "off");
    }
}
