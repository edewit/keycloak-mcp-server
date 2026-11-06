package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAddressCheck;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HostAddressCheckTest {

    private static String kind(String ip) throws Exception {
        return HostAddressCheck.privateKind(InetAddress.getByName(ip));
    }

    @Test
    void classifiesPrivateRanges() throws Exception {
        assertEquals("loopback", kind("127.0.0.1"));
        assertEquals("loopback", kind("::1"));
        assertEquals("site-local", kind("10.0.0.5"));
        assertEquals("site-local", kind("172.16.0.1"));
        assertEquals("site-local", kind("192.168.1.1"));
        assertEquals("link-local", kind("169.254.169.254"));
        assertEquals("link-local", kind("fe80::1"));
        assertEquals("unspecified", kind("0.0.0.0"));
        assertEquals("shared address space", kind("100.64.0.1"));
        assertEquals("unique local", kind("fd00::1"));
        assertEquals("multicast", kind("224.0.0.1"));
        assertEquals("reserved", kind("240.0.0.1"));
        assertEquals("benchmarking", kind("198.18.0.1"));
        assertNull(kind("8.8.8.8"));
        assertNull(kind("93.184.216.34"));
        assertNull(kind("2606:4700::1111"));
    }

    @Test
    void literalAddressesNeedNoDns() {
        assertTrue(HostAddressCheck.privateAddress("http://10.0.0.5:8080").orElseThrow().contains("site-local"));
        assertTrue(HostAddressCheck.privateAddress("http://[::1]:8080").orElseThrow().contains("loopback"));
        assertTrue(HostAddressCheck.privateAddress("http://localhost:8080").orElseThrow().contains("loopback"));
        assertEquals(Optional.empty(), HostAddressCheck.privateAddress("https://8.8.8.8"));
        assertEquals(Optional.of("no valid host"), HostAddressCheck.privateAddress("not a url"));
        assertEquals(Optional.of("no valid host"), HostAddressCheck.privateAddress("http://"));
    }

    @Test
    void allowAcceptsEverythingListedNeedsALiteralName() {
        HostAllowList wildcard = HostAllowList.of(List.of("*"));
        assertEquals(Optional.empty(), HostAddressCheck.refuse("http://127.0.0.1:8080", wildcard, PrivateHosts.ALLOW));
        assertEquals(Optional.empty(), HostAddressCheck.refuse("http://127.0.0.1:8080", HostAllowList.ANY, null));

        String why = HostAddressCheck.refuse("http://127.0.0.1:8080", wildcard, PrivateHosts.LISTED).orElseThrow();
        assertTrue(why.contains("loopback"), why);
        assertTrue(why.contains("dynamic-private-hosts=listed"), why);
        assertTrue(HostAddressCheck.refuse("http://10.0.0.5", HostAllowList.ANY, PrivateHosts.LISTED).isPresent(),
                "an unrestricted list names nothing literally");

        HostAllowList named = HostAllowList.of(List.of("keycloak:8080", "127.0.0.1", "*.internal"));
        assertEquals(Optional.empty(), HostAddressCheck.refuse("http://127.0.0.1:8080", named, PrivateHosts.LISTED));
        assertTrue(HostAddressCheck.refuse("http://10.0.0.5", named, PrivateHosts.LISTED).isPresent(),
                "the wildcard pattern does not count as naming the host");
        assertEquals(Optional.empty(), HostAddressCheck.refuse("https://8.8.8.8", named, PrivateHosts.LISTED),
                "public addresses pass without being listed");
    }

    @Test
    void allowListKnowsItsLiteralPatterns() {
        HostAllowList l = HostAllowList.of(List.of("*.example.com", "sso.example.com", "https://kc.internal:8443"));
        assertTrue(l.namesLiterally("https://sso.example.com/auth"));
        assertTrue(l.namesLiterally("https://SSO.example.com"));
        assertTrue(l.namesLiterally("https://kc.internal:8443"));
        assertTrue(!l.namesLiterally("http://kc.internal:8443"), "scheme of the literal pattern counts");
        assertTrue(!l.namesLiterally("https://other.example.com"), "wildcard match is not literal");
        assertTrue(!HostAllowList.ANY.namesLiterally("https://sso.example.com"));
    }
}
