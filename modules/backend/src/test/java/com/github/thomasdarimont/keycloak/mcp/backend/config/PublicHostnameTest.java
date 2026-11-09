package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminResource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicHostnameTest {

    @Test
    void acceptsAnOriginAndDropsATrailingSlash() {
        assertEquals("https://mcp.example.com", PublicHostname.normalize("https://mcp.example.com/"));
        assertEquals("http://mcp.internal:8081", PublicHostname.normalize(" http://mcp.internal:8081 "));
        assertEquals("mcp.internal:8081", PublicHostname.authority("http://mcp.internal:8081"));
        assertEquals(Optional.empty(), PublicHostname.of(Optional.of(" ")));
    }

    @Test
    void refusesAnythingButAnOrigin() {
        for (String bad : new String[] { "mcp.example.com", "ftp://mcp.example.com", "https://mcp.example.com/prefix",
                "https://mcp.example.com?a=b", "https://mcp.example.com#f", "https://user@mcp.example.com",
                "https://" }) {
            assertThrows(IllegalArgumentException.class, () -> PublicHostname.normalize(bad), bad);
        }
    }

    @Test
    void becomesTheProtectedResourceAndBadValuesStopTheStart() {
        assertEquals("https://mcp.example.com",
                HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.hostname", "https://mcp.example.com/"))
                    .getRawValue("quarkus.oidc.resource-metadata.resource"));
        assertThrows(IllegalArgumentException.class,
                () -> HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.hostname", "mcp.example.com"))
                    .getRawValue("quarkus.oidc.resource-metadata.resource"));
    }

    @Test
    void theJwksBaseIgnoresTheRequest() {
        assertEquals("https://mcp.example.com",
                AdminResource.publicBase(Optional.of("https://mcp.example.com/"), null, null));
    }
}
