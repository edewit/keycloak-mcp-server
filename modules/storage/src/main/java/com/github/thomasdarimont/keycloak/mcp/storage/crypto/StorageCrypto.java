package com.github.thomasdarimont.keycloak.mcp.storage.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;

/**
 * Encrypts private keys and secrets before they reach the database, AES-256-GCM with a
 * random nonce per value, when {@code kc-mcp.storage.secret-key} is set. Stored values
 * are {@code enc:v1:<base64 nonce>:<base64 ciphertext>}; a value without the prefix is
 * returned as is, so rows written before encryption was switched on stay readable.
 * Without a key values pass through unchanged. The key is the configured 32 bytes, or
 * derived from a passphrase with Argon2id ({@link #derive}); a subclass registered as a
 * CDI alternative can derive it differently, say from a KMS, or with other parameters.
 */
@ApplicationScoped
public class StorageCrypto {

    static final String PREFIX = "enc:v1:";
    private static final byte[] SALT = "keycloak-mcp-server-storage".getBytes(StandardCharsets.UTF_8);
    /**
     * Argon2id with the OWASP baseline: 19 MiB, 2 iterations, 1 lane; once at startup.
     */
    private static final int ARGON2_MEMORY_KIB = 19 * 1024;
    private static final int ARGON2_ITERATIONS = 2;
    private static final int ARGON2_LANES = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final String secret;
    private final ReentrantLock derivation = new ReentrantLock();
    private volatile SecretKey key;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public StorageCrypto(StorageConfig config) {
        this(config.secretKey().orElse(null));
    }

    /**
     * @param secret base64 of 32 bytes, a passphrase, or {@code null} for no encryption
     */
    public StorageCrypto(String secret) {
        this.secret = secret == null || secret.isBlank() ? null : secret.trim();
    }

    /** Whether values are encrypted at rest. */
    public boolean enabled() {
        return secret != null;
    }

    /**
     * The AES key, derived on first use (so a subclass is complete when {@link #derive}
     * runs).
     */
    protected final SecretKey key() {
        SecretKey k = key;
        if (k != null || secret == null) {
            return k;
        }
        derivation.lock();
        try {
            if (key == null) {
                key = derive(secret);
            }
            return key;
        }
        finally {
            derivation.unlock();
        }
    }

    /** The value as it is stored: encrypted when a key is configured, else unchanged. */
    public String protect(String plain) {
        if (plain == null || secret == null) {
            return plain;
        }
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return PREFIX + b64(nonce) + ":" + b64(ct);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot encrypt a stored value: " + e.getMessage(), e);
        }
    }

    /** The plain value of a stored one; a value without the encryption prefix as is. */
    public String reveal(String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            return stored;
        }
        if (secret == null) {
            throw new IllegalStateException(
                    "A stored value is encrypted but kc-mcp.storage.secret-key is not set; configure the key it was"
                            + " written with");
        }
        String[] parts = stored.substring(PREFIX.length()).split(":", 2);
        if (parts.length != 2) {
            throw new IllegalStateException("Malformed encrypted value");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(),
                    new GCMParameterSpec(TAG_BITS, Base64.getDecoder().decode(parts[0])));
            return new String(cipher.doFinal(Base64.getDecoder().decode(parts[1])), StandardCharsets.UTF_8);
        }
        catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(
                    "Cannot decrypt a stored value, kc-mcp.storage.secret-key differs from the key it was written with",
                    e);
        }
    }

    /**
     * A stable pseudonym of a value for audit records, {@code h:} and 16 hex digits:
     * HMAC-SHA256 under the configured key, so the same value maps to the same pseudonym
     * on every replica and nobody without the key can test guesses against it; without a
     * key a plain SHA-256, which still hides the value from a casual reader.
     */
    public String pseudonym(String value) {
        if (value == null) {
            return null;
        }
        try {
            byte[] digest;
            if (secret != null) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key().getEncoded(), "HmacSHA256"));
                digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            }
            else {
                digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            }
            return "h:" + HexFormat.of().formatHex(digest, 0, 8);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot pseudonymize a value: " + e.getMessage(), e);
        }
    }

    /** Whether a stored value carries the encryption prefix. */
    public static boolean isEncrypted(String stored) {
        return stored != null && stored.startsWith(PREFIX);
    }

    /**
     * The AES-256 key for the configured {@code kc-mcp.storage.secret-key}: 32 decoded
     * bytes are used as the key directly; anything else is a passphrase run through
     * Argon2id with a fixed, application-wide salt (the passphrase is an operator secret,
     * not a user password, and the derivation has to be reproducible on every replica
     * without a database round trip). Override to derive the key differently; the result
     * must be the same on every replica and across restarts.
     */
    protected SecretKey derive(String secret) {
        try {
            byte[] raw = Base64.getDecoder().decode(secret);
            if (raw.length == 32) {
                return new SecretKeySpec(raw, "AES");
            }
        }
        catch (IllegalArgumentException notBase64) {
            // a passphrase
        }
        Argon2BytesGenerator argon2 = new Argon2BytesGenerator();
        argon2.init(
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withSalt(SALT)
                    .withMemoryAsKB(ARGON2_MEMORY_KIB)
                    .withIterations(ARGON2_ITERATIONS)
                    .withParallelism(ARGON2_LANES)
                    .build());
        byte[] derived = new byte[32];
        argon2.generateBytes(secret.getBytes(StandardCharsets.UTF_8), derived);
        return new SecretKeySpec(derived, "AES");
    }

    protected String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
