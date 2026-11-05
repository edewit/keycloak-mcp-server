package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/** {@link AdminProfile} with {@code kc-mcp.admin.allow-new-systems=false}. */
public class ClosedRegistrationProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> m = new HashMap<>(new AdminProfile().getConfigOverrides());
        m.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-admin-closed-test;DB_CLOSE_DELAY=-1");
        m.put("kc-mcp.admin.allow-new-systems", "false");
        return m;
    }
}
