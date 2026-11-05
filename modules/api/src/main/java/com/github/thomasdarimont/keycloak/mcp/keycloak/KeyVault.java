package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps one signing key pair per Keycloak system for {@code private_key_jwt}, so that a
 * system only has to register this server's public key (served at
 * {@code /auth/keys/<system>/jwks.json}) and no secret is shared or stored anywhere. The
 * built-in vault keeps PEM files under {@code kc-mcp.keys-dir}; register your own
 * ({@code @AutoService(KeyVault.class)} or a CDI bean) to keep the keys in a database or
 * a secrets manager. The vault with the lowest {@link #order()} is used.
 */
public interface KeyVault extends Extension {

    /** The key of a system, created and stored on first use. */
    SigningKey keyFor(String system);

    /** The key of a system when one exists, without creating it. */
    Optional<SigningKey> find(String system);
}
