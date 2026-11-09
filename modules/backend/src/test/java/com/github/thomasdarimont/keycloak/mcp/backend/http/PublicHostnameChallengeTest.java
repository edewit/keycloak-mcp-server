package com.github.thomasdarimont.keycloak.mcp.backend.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicHostnameChallengeTest {

    @Test
    void replacesOnlyTheOriginOfTheLink() {
        assertEquals(
                "Bearer realm=\"x\", resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp/systems/a\"",
                PublicHostnameChallenge.rewrite(
                        "Bearer realm=\"x\", resource_metadata=\"http://evil.example:80/.well-known/oauth-protected-resource/mcp/systems/a\"",
                        "https://mcp.example.com"));
    }

    @Test
    void leavesOtherChallengesAlone() {
        assertEquals("Bearer realm=\"keycloak-mcp\"",
                PublicHostnameChallenge.rewrite("Bearer realm=\"keycloak-mcp\"", "https://mcp.example.com"));
    }
}
