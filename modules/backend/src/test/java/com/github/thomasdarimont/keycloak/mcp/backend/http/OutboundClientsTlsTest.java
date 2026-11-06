package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.tls.TlsConfigurationRegistry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A provider behind a private CA: an HTTPS server with a self-signed certificate is
 * reached through a named {@code quarkus.tls} configuration that trusts it, and refused
 * with the JVM's default trust.
 */
@QuarkusTest
@TestProfile(OutboundClientsTlsTest.Profile.class)
class OutboundClientsTlsTest {

    static final String PASSWORD = "changeit";
    static final Path DIR = Path.of("target", "outbound-tls");

    /**
     * Creates the key pair and the trust store before Quarkus reads the configuration.
     */
    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            stores();
            return Map.of("quarkus.tls.private-ca.trust-store.p12.path",
                    DIR.resolve("trust.p12").toAbsolutePath().toString(),
                    "quarkus.tls.private-ca.trust-store.p12.password", PASSWORD);
        }
    }

    static void stores() {
        // the profile and @BeforeAll both ask; the first run on the test thread creates
        // them
        if (Files.exists(DIR.resolve("trust.p12"))) {
            return;
        }
        try {
            Files.createDirectories(DIR);
            String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
            run(keytool, "-genkeypair", "-alias", "provider", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                    "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
                    "-keystore", DIR.resolve("server.p12").toString(), "-storepass", PASSWORD);
            run(keytool, "-exportcert", "-alias", "provider", "-keystore", DIR.resolve("server.p12").toString(),
                    "-storepass", PASSWORD, "-file", DIR.resolve("provider.cer").toString());
            run(keytool, "-importcert", "-noprompt", "-alias", "provider", "-file",
                    DIR.resolve("provider.cer").toString(), "-storetype", "PKCS12", "-keystore",
                    DIR.resolve("trust.p12").toString(), "-storepass", PASSWORD);
        }
        catch (Exception e) {
            throw new IllegalStateException("cannot create the test key stores", e);
        }
    }

    private static void run(String... command) throws Exception {
        Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) {
            throw new IllegalStateException(String.join(" ", command) + " failed: " + out);
        }
    }

    static HttpsServer server;
    static String url;

    @BeforeAll
    static void start() throws Exception {
        stores();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(new File(DIR.resolve("server.p12").toString()))) {
            ks.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, PASSWORD.toCharArray());
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ssl));
        server.createContext("/.well-known/openid-configuration", x -> {
            byte[] body = "{\"issuer\":\"private\"}".getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(200, body.length);
            try (OutputStream out = x.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        url = "https://localhost:" + server.getAddress().getPort() + "/.well-known/openid-configuration";
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Inject
    TlsConfigurationRegistry registry;

    @Test
    void theNamedConfigurationTrustsThePrivateCa() {
        Client client = OutboundClients.create("private-ca", registry, "test.tls");
        try (Response r = client.target(url).request().get()) {
            assertEquals(200, r.getStatus());
            assertTrue(r.readEntity(String.class).contains("private"));
        }
        finally {
            client.close();
        }
    }

    @Test
    void theDefaultTrustRefusesIt() {
        Client client = OutboundClients.create(null, registry, "test.tls");
        try {
            assertThrows(ProcessingException.class, () -> client.target(url).request().get().close());
        }
        finally {
            client.close();
        }
    }

    @Test
    void anUnknownNameIsAConfigurationError() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> OutboundClients.create("nope", registry, "kc-mcp.spi.ciba-confirmer.tls-configuration-name"));
        assertTrue(e.getMessage().contains("kc-mcp.spi.ciba-confirmer.tls-configuration-name=nope"), e.getMessage());
        assertTrue(e.getMessage().contains("quarkus.tls.nope"), e.getMessage());
    }
}
