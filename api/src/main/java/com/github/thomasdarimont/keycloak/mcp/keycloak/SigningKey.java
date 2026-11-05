package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * The key pair a system's {@code private_key_jwt} client assertions are signed with.
 *
 * @param algorithm JWS algorithm, e.g. {@code RS256}
 * @param keyId {@code kid} published in the JWKS and sent in the JWS header, {@code null}
 * for the RFC 7638 thumbprint
 */
public record SigningKey(PrivateKey privateKey, PublicKey publicKey, String algorithm, String keyId) {

    public SigningKey {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        algorithm = algorithm == null || algorithm.isBlank() ? "RS256" : algorithm;
    }
}
