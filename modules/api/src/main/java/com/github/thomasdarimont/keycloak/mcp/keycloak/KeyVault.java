package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps secrets for the server: one signing key pair per Keycloak system for
 * {@code private_key_jwt}, so that a system only has to register this server's public key
 * (served at {@code /auth/keys/<system>/jwks.json}) and no secret is shared or stored
 * anywhere, and raw secrets by name for the places that still need one (a client secret,
 * an API key), so configuration can hold references instead of values. The built-in vault
 * is read-only and serves PEM files under {@code kc-mcp.keys-dir} that operations
 * provisioned; register your own ({@code @AutoService(KeyVault.class)} or a CDI bean) to
 * keep keys and secrets in a database, which is also where keys get created and rotated
 * ({@link #supportsKeyCreation()}, with the {@link SigningKeyGenerator} the server hands
 * over), or in a secrets manager such as HashiCorp Vault. The vault with the lowest
 * {@link #order()} is used.
 */
public interface KeyVault extends Extension {

    /** The signing key pair of a system when one exists. */
    Optional<SigningKey> findSigningKey(String system);

    /**
     * Whether this vault can generate and store keys. The built-in file vault and a vault
     * backed by a secrets manager are read-only: keys are provisioned by operations and
     * the server only reads them; a system without a key is then an error, not a reason
     * to create one.
     */
    default boolean supportsKeyCreation() {
        return false;
    }

    /**
     * Generates and stores a new signing key pair for a system, replacing an existing one
     * (key rotation). Only when {@link #supportsKeyCreation()}; callers that want the
     * current key use {@link #findSigningKey} first.
     *
     * @throws UnsupportedOperationException for a read-only vault
     */
    default SigningKey createSigningKey(String system) {
        throw new UnsupportedOperationException(
                "KeyVault '" + id() + "' is read-only: provision a signing key for '" + system + "' in the vault");
    }

    /**
     * Handed the generator a creating vault should use ({@code kc-mcp.jwt.algorithm},
     * {@code kc-mcp.jwt.key-size}, or a registered {@link SigningKeyGenerator});
     * read-only vaults ignore it.
     */
    default void useSigningKeyGenerator(SigningKeyGenerator generator) {
    }

    /**
     * A raw secret by name ({@code tenant-a/client-secret}, {@code admin-api-key}), empty
     * when the vault has none. Read-only: secrets are put into the vault by other means.
     * Vaults that keep keys only leave the default.
     */
    default Optional<String> findSecret(String name) {
        return Optional.empty();
    }
}
