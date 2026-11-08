package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;

/**
 * {@link CustomRootPathTest} with the whole server under
 * {@code quarkus.http.root-path=/prefix} as well: the MCP endpoint is
 * {@code /prefix/review-mcp}, and the caller authentication, the entries, the metadata
 * and the 404s follow. RestAssured prefixes the root path itself.
 */
@QuarkusTest
@TestProfile(PrefixedRootPathTest.Profile.class)
class PrefixedRootPathTest extends CustomRootPathTest {

    public static class Profile extends CustomRootPathTest.Profile {
        @Override
        String jwksRoot() {
            return "/prefix";
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> config = new HashMap<>(super.getConfigOverrides());
            config.put("quarkus.http.root-path", "/prefix");
            return config;
        }
    }

    @Override
    String httpRoot() {
        return "/prefix";
    }
}
