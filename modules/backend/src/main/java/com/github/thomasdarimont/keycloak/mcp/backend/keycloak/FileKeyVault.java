package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

/**
 * The built-in, read-only {@link KeyVault}: keys and secrets that operations provisioned
 * as files under a directory ({@code kc-mcp.keys-dir}). A system's
 * {@code private_key_jwt} key is the PKCS#8 PEM {@code
 *
<dir>
 * /<system>.pem} ({@code openssl genpkey} writes that format), signing with
 * {@code kc-mcp.jwt.algorithm}; a raw secret is the file {@code
 *
<dir>
 * /secrets/<name>}. Nothing is ever written: a vault that creates and rotates keys is a
 * database-backed {@link KeyVault} extension.
 */
public final class FileKeyVault implements KeyVault {

    private static final Logger LOG = Logger.getLogger(FileKeyVault.class);

    private final Path dir;
    private final String algorithm;
    private final Map<String, SigningKey> loaded = new ConcurrentHashMap<>();

    public FileKeyVault(Path dir, String algorithm) {
        this.dir = dir;
        this.algorithm = algorithm == null || algorithm.isBlank() ? "RS256" : algorithm;
    }

    @Override
    public String id() {
        return "file";
    }

    @Override
    public String description() {
        return "provisioned PEM files under " + dir + " (read-only)";
    }

    public Path dir() {
        return dir;
    }

    @Override
    public Optional<SigningKey> findSigningKey(String system) {
        SigningKey k = loaded.get(system);
        if (k != null) {
            return Optional.of(k);
        }
        Path file = dir.resolve(safe(system) + ".pem");
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        return Optional.of(loaded.computeIfAbsent(system, s -> read(system, file)));
    }

    /**
     * A secret from the file {@code
     *
    <dir>
     * /secrets/<name>} (the name made file-safe, {@code tenant-a/client-secret} ->
     * {@code tenant-a_client-secret}), trimmed; empty when the file does not exist.
     */
    @Override
    public Optional<String> findSecret(String name) {
        Path file = dir.resolve("secrets").resolve(safe(name));
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        try {
            String value = Files.readString(file).trim();
            return value.isEmpty() ? Optional.empty() : Optional.of(value);
        }
        catch (IOException e) {
            throw new IllegalStateException("Cannot read the secret " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * The file names under {@code
     *
    <dir>
     * /secrets}, which are the names the secrets answer to.
     */
    @Override
    public List<String> secretNames() {
        Path secrets = dir.resolve("secrets");
        if (!Files.isDirectory(secrets)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(secrets)) {
            return files.filter(Files::isRegularFile).map(f -> f.getFileName().toString()).sorted().toList();
        }
        catch (IOException e) {
            throw new IllegalStateException("Cannot list " + secrets + ": " + e.getMessage(), e);
        }
    }

    private SigningKey read(String system, Path file) {
        try {
            PrivateKey key = JwtSigner.loadPem(file);
            LOG.infof("[%s] private_key_jwt key loaded from %s", system, file);
            return new SigningKey(key, Jwks.publicKeyOf(key), algorithm, null);
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot read the signing key " + file + ": " + e.getMessage(), e);
        }
    }

    private static String safe(String name) {
        return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "_");
    }
}
