package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The anonymous test endpoint is protected ({@code auto}): localhost clients pass, a page
 * that rebound its DNS name to 127.0.0.1 does not; other routes are untouched.
 */
@QuarkusTest
class DnsRebindingProtectionTest {

    static final String INIT = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
            + "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}";

    @Test
    void localhostPassesForeignHostsAndOriginsDoNot() {
        // RestAssured sends Host: localhost:<port>
        given().header("Accept", "application/json, text/event-stream")
            .contentType("application/json")
            .body(INIT)
            .post("/mcp")
            .then()
            .statusCode(200);
        given().header("Accept", "application/json, text/event-stream")
            .header("Host", "evil.example:8081")
            .contentType("application/json")
            .body(INIT)
            .post("/mcp")
            .then()
            .statusCode(403)
            .body("error", equalTo("forbidden_host"));
        given().header("Accept", "application/json, text/event-stream")
            .header("Origin", "http://evil.example")
            .contentType("application/json")
            .body(INIT)
            .post("/mcp")
            .then()
            .statusCode(403)
            .body("error", equalTo("forbidden_host"));
        given().header("Accept", "application/json, text/event-stream")
            .header("Origin", "http://127.0.0.1:5173")
            .contentType("application/json")
            .body(INIT)
            .post("/mcp")
            .then()
            .statusCode(200);
        // entries are below the root and covered as well
        given().header("Host", "evil.example").post("/mcp/systems/default").then().statusCode(403);
        // other routes are not the MCP endpoint
        given().header("Host", "evil.example").get("/.well-known/jwks.json").then().statusCode(404);
    }

    @Test
    void hostAndOriginParsing() {
        Set<String> none = Set.of();
        assertTrue(DnsRebindingProtection.permitted("localhost:8081", none));
        assertTrue(DnsRebindingProtection.permitted("127.0.0.1", none));
        assertTrue(DnsRebindingProtection.permitted("[::1]:8081", none));
        assertTrue(DnsRebindingProtection.permitted("LOCALHOST", none));
        assertFalse(DnsRebindingProtection.permitted("evil.example:8081", none));
        assertFalse(DnsRebindingProtection.permitted("", none));
        assertFalse(DnsRebindingProtection.permitted(null, none));
        Set<String> allowed = DnsRebindingProtection.allowedHosts(List.of("mcp.internal:8081", " Proxy.Example ", ""));
        assertTrue(DnsRebindingProtection.permitted("mcp.internal:8081", allowed), "host:port as configured");
        assertFalse(DnsRebindingProtection.permitted("mcp.internal:9999", allowed), "another port");
        assertTrue(DnsRebindingProtection.permitted("proxy.example:443", allowed), "host alone covers every port");
        assertTrue(DnsRebindingProtection.permittedOrigin("http://localhost:5173", none));
        assertTrue(DnsRebindingProtection.permittedOrigin("https://proxy.example", allowed));
        assertFalse(DnsRebindingProtection.permittedOrigin("http://evil.example", allowed));
        assertFalse(DnsRebindingProtection.permittedOrigin("not a url", none));
        assertEquals("[::1]", DnsRebindingProtection.hostOnly("[::1]:8081"));
        assertEquals("localhost", DnsRebindingProtection.hostOnly("localhost:8081"));
        assertEquals("::1", DnsRebindingProtection.hostOnly("::1"), "bare IPv6 keeps its colons");
    }
}
