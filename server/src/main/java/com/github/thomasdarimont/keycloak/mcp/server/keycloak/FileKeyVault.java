package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

/**
 * The built-in {@link KeyVault}: one PKCS#8 PEM file per system under a directory
 * ({@code kc-mcp.keys-dir}), RSA 2048, created on first use with owner-only permissions
 * where the file system supports them. Suitable for a single instance with a persistent
 * volume; several instances share the directory or use a vault of their own.
 */
public final class FileKeyVault implements KeyVault {

    private static final Logger LOG = Logger.getLogger(FileKeyVault.class);

    private final Path dir;
    private final String algorithm;
    private final Map<String, SigningKey> loaded = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    public FileKeyVault(Path dir, String algorithm) {
        this.dir = dir;
        this.algorithm = algorithm == null || algorithm.isBlank() ? "RS256" : algorithm;
    }

    @Override
    public String id() {
        return "file-key-vault";
    }

    @Override
    public String description() {
        return "PEM files under " + dir;
    }

    public Path dir() {
        return dir;
    }

    @Override
    public Optional<SigningKey> find(String system) {
        SigningKey k = loaded.get(system);
        if (k != null) {
            return Optional.of(k);
        }
        Path file = file(system);
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        lock.lock();
        try {
            return Optional.of(loaded.computeIfAbsent(system, s -> read(file)));
        }
        finally {
            lock.unlock();
        }
    }

    @Override
    public SigningKey keyFor(String system) {
        Optional<SigningKey> existing = find(system);
        if (existing.isPresent()) {
            return existing.get();
        }
        lock.lock();
        try {
            return loaded.computeIfAbsent(system, s -> Files.isRegularFile(file(s)) ? read(file(s)) : create(s));
        }
        finally {
            lock.unlock();
        }
    }

    private Path file(String system) {
        String safe = system.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "_");
        return dir.resolve(safe + ".pem");
    }

    private SigningKey read(Path file) {
        try {
            PrivateKey key = JwtSigner.loadPem(file);
            return new SigningKey(key, Jwks.publicKeyOf(key), algorithm, null);
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot read the signing key " + file + ": " + e.getMessage(), e);
        }
    }

    private SigningKey create(String system) {
        Path file = file(system);
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            Files.createDirectories(dir);
            String pem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(pair.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
            Path tmp = Files.createTempFile(dir, "." + file.getFileName(), ".tmp");
            Files.writeString(tmp, pem, StandardCharsets.US_ASCII);
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            }
            catch (UnsupportedOperationException ignored) {
                // not a POSIX file system
            }
            Files.move(tmp, file);
            LOG.infof("[%s] generated a private_key_jwt key, stored in %s", system, file);
            return new SigningKey(pair.getPrivate(), pair.getPublic(), algorithm, null);
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Cannot create the signing key for '" + system + "' in " + dir + ": " + e.getMessage(), e);
        }
    }
}
