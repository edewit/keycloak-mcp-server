package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TruststoreInterceptorFactoryTest {

    @TempDir
    Path dir;

    private Path copy(String resource, String target) throws Exception {
        Path file = dir.resolve(target);
        Files.createDirectories(file.getParent());
        try (InputStream in = getClass().getResourceAsStream("/truststore/" + resource)) {
            Files.copy(in, file);
        }
        return file;
    }

    private static List<String> subjects(List<Certificate> certificates) {
        return certificates.stream().map(c -> ((X509Certificate) c).getSubjectX500Principal().getName()).toList();
    }

    @Test
    void readsPemAndUnencryptedPkcs12FilesAndDirectoriesRecursively() throws Exception {
        copy("a.pem", "certs/a.pem");
        copy("b.p12", "certs/nested/deeper/b.p12");
        Files.writeString(dir.resolve("certs/README.md"), "not a certificate");
        assertEquals(List.of("CN=kc-mcp-test-a", "CN=kc-mcp-test-b"),
                subjects(TruststoreInterceptorFactory.certificates(List.of(dir.resolve("certs")))));
    }

    @Test
    void theJvmsDefaultCertificatesStayTrusted() throws Exception {
        KeyStore base = TruststoreInterceptorFactory.defaultTrust();
        List<Certificate> added = TruststoreInterceptorFactory.certificates(List.of(copy("a.pem", "a.pem")));
        KeyStore merged = TruststoreInterceptorFactory.merge(base, added);
        assertTrue(base.size() > 0);
        assertEquals(base.size() + 1, merged.size());
        assertTrue(merged.getCertificateAlias(added.getFirst()) != null);
    }

    @Test
    void aListedPathMustExistButTheDefaultDirectoryIsOptional() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> TruststoreInterceptorFactory.configured(dir.resolve("missing.pem").toString(), Optional.empty()));
        assertEquals(List.of(), TruststoreInterceptorFactory.configured(null, DistributionHome.of(dir.toString())));
        Path defaults = Files.createDirectories(dir.resolve("conf/truststores"));
        Path listed = copy("a.pem", "a.pem");
        assertEquals(List.of(listed, defaults), TruststoreInterceptorFactory.configured("${kcmcp.home.dir}/a.pem",
                DistributionHome.of(dir.toString())));
    }

    @Test
    void aFileWithoutCertificatesIsRefused() throws Exception {
        Path empty = Files.writeString(dir.resolve("empty.pem"), "");
        assertThrows(IllegalArgumentException.class, () -> TruststoreInterceptorFactory.certificates(List.of(empty)));
    }
}
