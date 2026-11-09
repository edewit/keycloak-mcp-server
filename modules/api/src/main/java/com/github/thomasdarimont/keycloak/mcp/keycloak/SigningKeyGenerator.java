package com.github.thomasdarimont.keycloak.mcp.keycloak;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Generates the key pairs a {@link KeyVault} stores for {@code private_key_jwt}, for a
 * JWS algorithm ({@code kc-mcp.jwt.algorithm}). The built-in
 * {@link DefaultSigningKeyGenerator} uses the JDK; register your own
 * ({@code @AutoService(SigningKeyGenerator.class)} or a CDI bean) to generate keys in an
 * HSM or with other parameters. The generator with the lowest {@link #order()} is used.
 */
public interface SigningKeyGenerator extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.key-generator.<id>.*}.
     */
    String SPI = "key-generator";

    @Override
    default String spiName() {
        return SPI;
    }

    /** Whether keys for this JWS algorithm can be generated. */
    boolean supports(String algorithm);

    /**
     * A new key pair for the algorithm, with the {@code kid} left to the vault or the
     * signer ({@code null} means the RFC 7638 thumbprint).
     *
     * @throws IllegalArgumentException for an algorithm {@link #supports} denies
     */
    SigningKey generate(String algorithm);
}
