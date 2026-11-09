package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;

/**
 * Keycloak's system truststore: the certificates in {@code conf/truststores} of the
 * distribution and in {@code kc-mcp.truststore-paths} (PEM files, unencrypted PKCS12
 * files, directories of them, searched recursively) are trusted in addition to the JVM's
 * default certificates, by everything in the JVM that uses the default trust: the
 * Keycloak admin client, OIDC discovery and key retrieval, the database driver. The
 * merged store is written to a temporary file named by the
 * {@code javax.net.ssl.trustStore} properties. Without additional certificates nothing
 * changes. An interceptor because those properties must be set before the OIDC recorder's
 * first connection, which is ahead of any startup event, and after the configuration
 * files have been read.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class TruststoreInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String PROPERTY = "kc-mcp.truststore-paths";

    private static final char[] PASSWORD = "changeit".toCharArray();

    private static final AtomicReference<List<Path>> INSTALLED = new AtomicReference<>();

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return (ctx, name) -> {
            ConfigValue value = ctx.proceed(name);
            if (PROPERTY.equals(name)) {
                install(configured(value == null ? null : value.getValue(), DistributionHome.current()));
            }
            return value;
        };
    }

    /** The configured paths, then the distribution's {@code conf/truststores}. */
    static List<Path> configured(String paths, Optional<DistributionHome> home) {
        List<Path> result = new ArrayList<>();
        if (paths != null) {
            for (String entry : paths.split(",")) {
                String path = entry.trim();
                if (!path.isEmpty()) {
                    Path p = Path.of(home.map(h -> h.expand(path)).orElse(path));
                    if (!Files.exists(p)) {
                        throw new IllegalArgumentException(PROPERTY + ": not found: " + p);
                    }
                    result.add(p);
                }
            }
        }
        home.map(h -> h.resolve("conf", "truststores")).filter(Files::isDirectory).ifPresent(result::add);
        return result;
    }

    /** The configuration is built more than once in a start; merge once per value. */
    private static void install(List<Path> paths) {
        if (paths.equals(INSTALLED.getAndSet(paths))) {
            return;
        }
        List<Certificate> additional = certificates(paths);
        if (additional.isEmpty()) {
            return;
        }
        try {
            KeyStore merged = merge(defaultTrust(), additional);
            Path file = Files.createTempFile("kc-mcp-truststore", ".p12");
            file.toFile().deleteOnExit();
            try (OutputStream out = Files.newOutputStream(file)) {
                merged.store(out, PASSWORD);
            }
            System.setProperty("javax.net.ssl.trustStore", file.toString());
            System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
            System.setProperty("javax.net.ssl.trustStorePassword", new String(PASSWORD));
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(PROPERTY + ": cannot build the truststore: " + e.getMessage(), e);
        }
    }

    /** The certificates of the files and directories. */
    static List<Certificate> certificates(List<Path> paths) {
        List<Certificate> result = new ArrayList<>();
        for (Path path : paths) {
            try {
                if (Files.isDirectory(path)) {
                    try (Stream<Path> files = Files.walk(path)) {
                        for (Path file : files.filter(TruststoreInterceptorFactory::isCertificateFile)
                            .sorted()
                            .toList()) {
                            result.addAll(read(file));
                        }
                    }
                }
                else {
                    result.addAll(read(path));
                }
            }
            catch (IOException | GeneralSecurityException e) {
                throw new IllegalArgumentException(PROPERTY + ": cannot read " + path + ": " + e.getMessage(), e);
            }
        }
        return result;
    }

    private static boolean isCertificateFile(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return Files.isRegularFile(path)
                && (isPkcs12(name) || name.endsWith(".pem") || name.endsWith(".crt") || name.endsWith(".cer"));
    }

    private static boolean isPkcs12(String name) {
        return name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12");
    }

    private static Collection<? extends Certificate> read(Path file) throws IOException, GeneralSecurityException {
        Collection<? extends Certificate> certificates;
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file))) {
            if (isPkcs12(file.getFileName().toString().toLowerCase(Locale.ROOT))) {
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(in, null);
                certificates = entries(store);
            }
            else {
                certificates = CertificateFactory.getInstance("X.509").generateCertificates(in);
            }
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException(PROPERTY + ": no certificates in " + file
                    + " (a PKCS12 file must be unencrypted, a PEM file must hold certificates)");
        }
        return certificates;
    }

    private static List<Certificate> entries(KeyStore store) throws GeneralSecurityException {
        List<Certificate> result = new ArrayList<>();
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            Certificate certificate = store.getCertificate(aliases.nextElement());
            if (certificate != null) {
                result.add(certificate);
            }
        }
        return result;
    }

    /** The JVM's default certificates and the additional ones, in a new store. */
    static KeyStore merge(KeyStore base, List<Certificate> additional) throws IOException, GeneralSecurityException {
        KeyStore merged = KeyStore.getInstance("PKCS12");
        merged.load(null, null);
        int n = 0;
        for (Certificate certificate : entries(base)) {
            merged.setCertificateEntry("default-" + n++, certificate);
        }
        for (Certificate certificate : additional) {
            merged.setCertificateEntry("additional-" + n++, certificate);
        }
        return merged;
    }

    /**
     * What the JVM would trust: the {@code javax.net.ssl.trustStore} property, else
     * {@code jssecacerts}, else {@code cacerts}.
     */
    static KeyStore defaultTrust() throws IOException, GeneralSecurityException {
        Path security = Path.of(System.getProperty("java.home"), "lib", "security");
        String configured = System.getProperty("javax.net.ssl.trustStore");
        Path file = configured != null ? Path.of(configured) : Files.exists(security.resolve("jssecacerts"))
                ? security.resolve("jssecacerts") : security.resolve("cacerts");
        String type = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
        String password = System.getProperty("javax.net.ssl.trustStorePassword");
        KeyStore store = KeyStore.getInstance(type);
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, password == null ? null : password.toCharArray());
        }
        return store;
    }

}
