package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Locale;
import java.util.Set;

/**
 * JDK key pairs by JWS algorithm: RSA for {@code RS256/384/512} and {@code PS256/384/512}
 * (size configurable, 2048 by default), EC for {@code ES256} (P-256), {@code ES384}
 * (P-384) and {@code ES512} (P-521).
 */
public class DefaultSigningKeyGenerator implements SigningKeyGenerator {

    public static final int DEFAULT_RSA_KEY_SIZE = 2048;

    private static final Set<String> RSA = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    private final int rsaKeySize;

    public DefaultSigningKeyGenerator() {
        this(DEFAULT_RSA_KEY_SIZE);
    }

    /** @param rsaKeySize modulus bits of RSA keys, 2048 or more */
    public DefaultSigningKeyGenerator(int rsaKeySize) {
        if (rsaKeySize < 2048) {
            throw new IllegalArgumentException("RSA keys need at least 2048 bits, not " + rsaKeySize);
        }
        this.rsaKeySize = rsaKeySize;
    }

    @Override
    public String id() {
        return "default";
    }

    @Override
    public String description() {
        return "JDK generated RSA (" + rsaKeySize + " bit) and EC keys";
    }

    @Override
    public boolean supports(String algorithm) {
        String alg = normalize(algorithm);
        return RSA.contains(alg) || curveOf(alg) != null;
    }

    @Override
    public SigningKey generate(String algorithm) {
        String alg = normalize(algorithm);
        try {
            KeyPair pair;
            if (RSA.contains(alg)) {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(rsaKeySize);
                pair = gen.generateKeyPair();
            }
            else if (curveOf(alg) != null) {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(new ECGenParameterSpec(curveOf(alg)));
                pair = gen.generateKeyPair();
            }
            else {
                throw new IllegalArgumentException("Cannot generate keys for the JWS algorithm '" + algorithm
                        + "'; supported: " + RSA + " and ES256, ES384, ES512");
            }
            return new SigningKey(pair.getPrivate(), pair.getPublic(), alg, null);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot generate a " + alg + " key: " + e.getMessage(), e);
        }
    }

    private static String normalize(String algorithm) {
        return algorithm == null ? "" : algorithm.trim().toUpperCase(Locale.ROOT);
    }

    private static String curveOf(String alg) {
        return switch (alg) {
            case "ES256" -> "secp256r1";
            case "ES384" -> "secp384r1";
            case "ES512" -> "secp521r1";
            default -> null;
        };
    }
}
