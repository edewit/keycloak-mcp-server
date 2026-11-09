package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpsInterceptorFactoryTest {

    static SmallRyeConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder().withInterceptorFactories(new HttpsInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
    }

    @Test
    void aPemPairBecomesTheServerCertificateAndIsFoundByName() {
        SmallRyeConfig c = config(Map.of("kc-mcp.https-certificate-file", "c.pem", "kc-mcp.https-certificate-key-file",
                "k.pem", "kc-mcp.https-port", "9443", "kc-mcp.http-enabled", "false"));
        assertEquals("c.pem", c.getRawValue("quarkus.tls.key-store.pem.server.cert"));
        assertEquals("k.pem", c.getRawValue("quarkus.tls.key-store.pem.server.key"));
        assertEquals("9443", c.getRawValue("quarkus.http.ssl-port"));
        assertEquals("disabled", c.getRawValue("quarkus.http.insecure-requests"));
        assertEquals("1h", c.getRawValue("quarkus.tls.reload-period"), "Keycloak's default");
        assertTrue(c.isPropertyPresent("quarkus.tls.key-store.pem.server.cert"));
        boolean named = false;
        for (String name : c.getPropertyNames()) {
            named |= name.equals("quarkus.tls.key-store.pem.server.cert");
        }
        assertTrue(named, "the TLS mapping finds its keys by name");
    }

    @Test
    void theKeyStoreTypeFollowsTheExtensionAndThePemPairWins() {
        SmallRyeConfig c = config(Map.of("kc-mcp.https-key-store-file", "server.pfx"));
        assertEquals("server.pfx", c.getRawValue("quarkus.tls.key-store.p12.path"));
        assertEquals("password", c.getRawValue("quarkus.tls.key-store.p12.password"), "Keycloak's default");
        assertEquals("jks", HttpsInterceptorFactory.keyStoreType("server.keystore", null));
        assertEquals("jks", HttpsInterceptorFactory.keyStoreType("server.bin", "JKS"));
        assertThrows(IllegalArgumentException.class, () -> HttpsInterceptorFactory.keyStoreType("server.bin", null));
        SmallRyeConfig both = config(Map.of("kc-mcp.https-key-store-file", "s.p12", "kc-mcp.https-certificate-file",
                "c.pem", "kc-mcp.https-certificate-key-file", "k.pem"));
        assertNull(both.getRawValue("quarkus.tls.key-store.p12.path"));
        assertEquals("c.pem", both.getRawValue("quarkus.tls.key-store.pem.server.cert"));
    }

    @Test
    void aDirectQuarkusValueWinsAndReloadCanBeSwitchedOff() {
        Map<String, String> p = new HashMap<>(Map.of("kc-mcp.https-certificate-file", "c.pem",
                "kc-mcp.https-certificate-key-file", "k.pem", "kc-mcp.https-certificates-reload-period", "-1"));
        p.put("quarkus.tls.key-store.pem.server.cert", "direct.pem");
        SmallRyeConfig c = config(p);
        assertEquals("direct.pem", c.getRawValue("quarkus.tls.key-store.pem.server.cert"));
        assertNull(c.getRawValue("quarkus.tls.reload-period"));
    }

    @Test
    void theOptionsBeatTheJarsDefaults() {
        SmallRyeConfig c = new SmallRyeConfigBuilder().withInterceptorFactories(new HttpsInterceptorFactory())
            .withSources(new PropertiesConfigSource(
                    Map.of("quarkus.http.ssl-port", "8443", "quarkus.http.insecure-requests", "enabled"), "jar", 250))
            .withSources(new PropertiesConfigSource(Map.of("kc-mcp.https-port", "9443", "kc-mcp.http-enabled", "false"),
                    "conf", 275))
            .build();
        assertEquals("9443", c.getRawValue("quarkus.http.ssl-port"));
        assertEquals("disabled", c.getRawValue("quarkus.http.insecure-requests"));
    }

    @Test
    void halfAPemPairIsRefused() {
        SmallRyeConfig c = config(Map.of("kc-mcp.https-certificate-file", "c.pem"));
        assertThrows(IllegalArgumentException.class, () -> c.getRawValue("quarkus.tls.reload-period"));
    }
}
