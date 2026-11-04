package org.keycloak.mcp.keycloak;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import io.vertx.core.json.JsonObject;

/**
 * JWK helpers for the {@code private_key_jwt} key: public key derivation, JWK encoding
 * and the RFC 7638 thumbprint used as default {@code kid}. No external JOSE dependency.
 */
public final class Jwks {

    private Jwks() {
    }

    /**
     * Derives the public key from a private key: RSA via the CRT parameters, EC via
     * scalar multiplication.
     */
    public static PublicKey publicKeyOf(PrivateKey key) throws GeneralSecurityException {
        if (key instanceof RSAPrivateCrtKey rsa) {
            return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
        }
        if (key instanceof ECPrivateKey ec) {
            return deriveEcPublic(ec);
        }
        throw new GeneralSecurityException("Cannot derive a public key from " + key.getClass().getName()
                + "; configure kc-mcp.jwt.public-key-file");
    }

    /** Loads a {@code BEGIN PUBLIC KEY} or {@code BEGIN CERTIFICATE} PEM. */
    public static PublicKey loadPublicKeyPem(Path file) throws IOException, GeneralSecurityException {
        String pem = Files.readString(file, StandardCharsets.US_ASCII);
        if (pem.contains("BEGIN CERTIFICATE")) {
            return CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(file))
                .getPublicKey();
        }
        String body = pem.replaceAll("-----(BEGIN|END)[A-Z ]*-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        for (String alg : new String[] { "RSA", "EC" }) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
            }
            catch (GeneralSecurityException ignored) {
                // try next
            }
        }
        throw new GeneralSecurityException("PEM does not contain an RSA or EC public key");
    }

    /** JWK for a public key; {@code alg} and {@code kid} are added when given. */
    public static JsonObject jwk(PublicKey key, String alg, String kid) {
        JsonObject jwk;
        if (key instanceof RSAPublicKey rsa) {
            jwk = new JsonObject().put("kty", "RSA")
                .put("n", b64(unsigned(rsa.getModulus())))
                .put("e", b64(unsigned(rsa.getPublicExponent())));
        }
        else if (key instanceof ECPublicKey ec) {
            int len = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            jwk = new JsonObject().put("kty", "EC")
                .put("crv", curveName(ec.getParams()))
                .put("x", b64(fixed(ec.getW().getAffineX(), len)))
                .put("y", b64(fixed(ec.getW().getAffineY(), len)));
        }
        else {
            throw new IllegalArgumentException("Unsupported key type " + key.getAlgorithm());
        }
        jwk.put("use", "sig");
        if (alg != null) {
            jwk.put("alg", alg);
        }
        jwk.put("kid", kid != null && !kid.isBlank() ? kid : thumbprint(jwk));
        return jwk;
    }

    /** RFC 7638 SHA-256 thumbprint over the required members in lexicographic order. */
    public static String thumbprint(JsonObject jwk) {
        String canonical = switch (jwk.getString("kty")) {
            case "RSA" -> "{\"e\":\"" + jwk.getString("e") + "\",\"kty\":\"RSA\",\"n\":\"" + jwk.getString("n") + "\"}";
            case "EC" -> "{\"crv\":\"" + jwk.getString("crv") + "\",\"kty\":\"EC\",\"x\":\"" + jwk.getString("x")
                    + "\",\"y\":\"" + jwk.getString("y") + "\"}";
            default -> throw new IllegalArgumentException("Unsupported kty " + jwk.getString("kty"));
        };
        try {
            return b64(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String curveName(ECParameterSpec params) {
        return switch (params.getCurve().getField().getFieldSize()) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalArgumentException(
                    "Unsupported EC curve size " + params.getCurve().getField().getFieldSize());
        };
    }

    /**
     * Q = d * G on a prime curve, affine double-and-add; the JDK offers no public API for
     * this.
     */
    static ECPublicKey deriveEcPublic(ECPrivateKey key) throws GeneralSecurityException {
        ECParameterSpec params = key.getParams();
        if (!(params.getCurve().getField() instanceof ECFieldFp field)) {
            throw new GeneralSecurityException("Only prime field EC curves are supported");
        }
        BigInteger p = field.getP();
        BigInteger a = params.getCurve().getA();
        ECPoint q = multiply(params.getGenerator(), key.getS(), a, p);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(q, params));
    }

    private static ECPoint multiply(ECPoint g, BigInteger k, BigInteger a, BigInteger p) {
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = g;
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                result = add(result, addend, a, p);
            }
            addend = add(addend, addend, a, p);
        }
        return result;
    }

    private static ECPoint add(ECPoint p1, ECPoint p2, BigInteger a, BigInteger p) {
        if (p1.equals(ECPoint.POINT_INFINITY)) {
            return p2;
        }
        if (p2.equals(ECPoint.POINT_INFINITY)) {
            return p1;
        }
        BigInteger x1 = p1.getAffineX();
        BigInteger y1 = p1.getAffineY();
        BigInteger x2 = p2.getAffineX();
        BigInteger y2 = p2.getAffineY();
        BigInteger lambda;
        if (x1.equals(x2)) {
            if (y1.add(y2).mod(p).signum() == 0) {
                return ECPoint.POINT_INFINITY;
            }
            // doubling: (3x^2 + a) / (2y)
            lambda = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a).multiply(y1.shiftLeft(1).modInverse(p)).mod(p);
        }
        else {
            lambda = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
        }
        BigInteger x3 = lambda.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new ECPoint(x3, y3);
    }

    static byte[] unsigned(BigInteger i) {
        byte[] b = i.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            return t;
        }
        return b;
    }

    static byte[] fixed(BigInteger i, int length) {
        byte[] u = unsigned(i);
        if (u.length == length) {
            return u;
        }
        byte[] out = new byte[length];
        System.arraycopy(u, 0, out, length - u.length, u.length);
        return out;
    }

    static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
