package com.github.thomasdarimont.keycloak.mcp.storage;

import java.util.List;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Settings of the storage module ({@code kc-mcp.storage.*}, env
 * {@code KC_MCP_STORAGE_*}). The database connection itself is the Quarkus default
 * datasource ({@code quarkus.datasource.jdbc.url}, {@code username}, {@code password}).
 */
@ConfigMapping(prefix = "kc-mcp.storage")
public interface StorageConfig {

    /**
     * Whether systems, keys, secrets and audit events are kept in the database. Defaults
     * to whether {@code quarkus.datasource.jdbc.url} is configured
     * ({@link StorageConfigSourceFactory}); {@code false} keeps a configured datasource
     * unused, {@code true} without a datasource fails at startup.
     */
    @WithDefault("false")
    boolean enabled();

    /**
     * Key that encrypts private keys and secrets at rest (AES-256-GCM): the base64 of 32
     * random bytes ({@code openssl rand -base64 32}), or any passphrase, from which the
     * key is derived with Argon2id. Unset stores them in plain text, which the startup
     * log warns about. Rows written without encryption stay readable after the key is
     * set; rows written with it need the same key.
     */
    Optional<String> secretKey();

    /**
     * Keys rotated away ({@code KC_MCP_STORAGE_PREVIOUS_SECRET_KEYS}, comma separated):
     * they still decrypt values written under them, never encrypt. With one configured,
     * {@code StorageRekey} rewrites every encrypted row under {@link #secretKey()} at
     * startup; afterwards the old key can be removed.
     */
    Optional<List<String>> previousSecretKeys();
}
