package com.github.thomasdarimont.keycloak.mcp.server.keycloak;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.Locale;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.vertx.core.json.JsonObject;

/**
 * Minimal JWS signer for client assertions: RS*, PS* and ES* with keys from a PKCS#8 PEM
 * file or a keystore. No external JOSE dependency.
 */
public final class JwtSigner {

    private final PrivateKey key;
    private final PublicKey publicKey;
    private final String algorithm;
    private final String keyId;
    private final JsonObject jwk;

    public JwtSigner(PrivateKey key, String algorithm, String keyId) {
        this(key, null, algorithm, keyId);
    }

    /**
     * @param publicKey the matching public key; derived from the private key when
     * {@code null}
     * @param keyId {@code kid} to put in the JWS header and the JWK; RFC 7638 thumbprint
     * when {@code null}
     */
    public JwtSigner(PrivateKey key, PublicKey publicKey, String algorithm, String keyId) {
        this.key = key;
        this.algorithm = algorithm.toUpperCase(Locale.ROOT);
        checkKeyMatchesAlgorithm();
        try {
            this.publicKey = publicKey != null ? publicKey : Jwks.publicKeyOf(key);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot derive the public key: " + e.getMessage(), e);
        }
        this.jwk = Jwks.jwk(this.publicKey, this.algorithm, keyId);
        this.keyId = jwk.getString("kid");
    }

    public static JwtSigner fromConfig(McpServerConfig.Jwt jwt) {
        try {
            PrivateKey key;
            PublicKey publicKey = null;
            if (jwt.keyFile().isPresent()) {
                key = loadPem(Path.of(jwt.keyFile().get()));
            }
            else if (jwt.keystoreFile().isPresent()) {
                KeyStore ks = openKeystore(Path.of(jwt.keystoreFile().get()), jwt.keystoreType(),
                        jwt.keystorePassword().orElse(""));
                String alias = keyAlias(ks, jwt.keyAlias().orElse(null));
                key = privateKey(ks, alias, jwt.keyPassword().or(jwt::keystorePassword).orElse(""));
                java.security.cert.Certificate cert = ks.getCertificate(alias);
                publicKey = cert == null ? null : cert.getPublicKey();
            }
            else {
                throw new IllegalStateException(
                        "Missing configuration 'kc-mcp.jwt.key-file' or 'kc-mcp.jwt.keystore-file' for auth mode private_key_jwt");
            }
            if (jwt.publicKeyFile().isPresent()) {
                publicKey = Jwks.loadPublicKeyPem(Path.of(jwt.publicKeyFile().get()));
            }
            return new JwtSigner(key, publicKey, jwt.algorithm(), jwt.keyId().orElse(null));
        }
        catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot load private key for private_key_jwt: " + e.getMessage(), e);
        }
    }

    public String algorithm() {
        return algorithm;
    }

    public String keyId() {
        return keyId;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    /** Public JWK of the signing key, as served by the JWKS endpoint. */
    public JsonObject jwk() {
        return jwk.copy();
    }

    public String sign(JsonObject claims) {
        JsonObject header = new JsonObject().put("alg", algorithm).put("typ", "JWT");
        if (keyId != null && !keyId.isBlank()) {
            header.put("kid", keyId);
        }
        String signingInput = b64(header.encode().getBytes(StandardCharsets.UTF_8)) + "."
                + b64(claims.encode().getBytes(StandardCharsets.UTF_8));
        try {
            Signature sig = Signature.getInstance(jcaName(algorithm));
            if (algorithm.startsWith("PS")) {
                String digest = "SHA-" + algorithm.substring(2);
                int saltLen = Integer.parseInt(algorithm.substring(2)) / 8;
                sig.setParameter(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), saltLen, 1));
            }
            sig.initSign(key);
            sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] signature = sig.sign();
            if (algorithm.startsWith("ES")) {
                signature = derToJose(signature, ecPartLength(algorithm));
            }
            return signingInput + "." + b64(signature);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Signing client assertion failed: " + e.getMessage(), e);
        }
    }

    private void checkKeyMatchesAlgorithm() {
        boolean ec = algorithm.startsWith("ES");
        if (ec && !(key instanceof ECPrivateKey)) {
            throw new IllegalStateException(algorithm + " needs an EC private key");
        }
        if (!ec && !(key instanceof RSAPrivateKey)) {
            throw new IllegalStateException(algorithm + " needs an RSA private key");
        }
    }

    static String jcaName(String alg) {
        return switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "PS256", "PS384", "PS512" -> "RSASSA-PSS";
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            default -> throw new IllegalStateException("Unsupported JWT algorithm " + alg);
        };
    }

    private static int ecPartLength(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            default -> 66;
        };
    }

    /**
     * Converts a DER encoded ECDSA signature to the fixed-size R||S form JOSE requires.
     */
    static byte[] derToJose(byte[] der, int partLength) {
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset += der[1] & 0x7f;
        }
        int rLen = der[offset + 1];
        byte[] r = new BigInteger(1, java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + rLen)).toByteArray();
        offset += 2 + rLen;
        int sLen = der[offset + 1];
        byte[] s = new BigInteger(1, java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + sLen)).toByteArray();
        byte[] out = new byte[partLength * 2];
        copyRightAligned(r, out, 0, partLength);
        copyRightAligned(s, out, partLength, partLength);
        return out;
    }

    private static void copyRightAligned(byte[] src, byte[] dst, int dstStart, int length) {
        int skip = Math.max(0, src.length - length);
        int n = src.length - skip;
        System.arraycopy(src, skip, dst, dstStart + (length - n), n);
    }

    static PrivateKey loadPem(Path file) throws IOException, GeneralSecurityException {
        String pem = Files.readString(file, StandardCharsets.US_ASCII);
        return parsePem(pem);
    }

    static PrivateKey parsePem(String pem) throws GeneralSecurityException {
        if (pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN EC PRIVATE KEY")) {
            throw new GeneralSecurityException("PKCS#1/SEC1 keys are not supported; convert with "
                    + "'openssl pkcs8 -topk8 -nocrypt' to a 'BEGIN PRIVATE KEY' PEM");
        }
        if (pem.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
            throw new GeneralSecurityException("Encrypted PEM keys are not supported; use a keystore instead");
        }
        String body = pem.replaceAll("-----(BEGIN|END)[A-Z ]*-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        for (String alg : new String[] { "RSA", "EC" }) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            }
            catch (GeneralSecurityException ignored) {
                // try next
            }
        }
        throw new GeneralSecurityException("PEM does not contain an RSA or EC PKCS#8 private key");
    }

    static PrivateKey loadKeystore(Path file, String type, String storePassword, String alias, String keyPassword)
            throws IOException, GeneralSecurityException {
        KeyStore ks = openKeystore(file, type, storePassword);
        return privateKey(ks, keyAlias(ks, alias), keyPassword);
    }

    static KeyStore openKeystore(Path file, String type, String storePassword)
            throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(type);
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, storePassword.toCharArray());
        }
        return ks;
    }

    static String keyAlias(KeyStore ks, String alias) throws GeneralSecurityException {
        if (alias != null) {
            return alias;
        }
        var aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String candidate = aliases.nextElement();
            if (ks.isKeyEntry(candidate)) {
                return candidate;
            }
        }
        throw new GeneralSecurityException("Keystore has no private key entry");
    }

    static PrivateKey privateKey(KeyStore ks, String alias, String keyPassword) throws GeneralSecurityException {
        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey pk)) {
            throw new GeneralSecurityException("Alias '" + alias + "' is not a private key");
        }
        return pk;
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
