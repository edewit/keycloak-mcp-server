package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * Like the dynamic-systems example: no static system, systems arrive through the admin
 * API.
 */
public class NoSystemsProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> m = new HashMap<>(new AdminProfile().getConfigOverrides());
        m.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-no-systems-test;DB_CLOSE_DELAY=-1");
        m.put("kc-mcp.static-systems", "false");
        return m;
    }
}
