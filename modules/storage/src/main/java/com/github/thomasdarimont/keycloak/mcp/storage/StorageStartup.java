package com.github.thomasdarimont.keycloak.mcp.storage;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.runtime.StartupEvent;

/** Says at startup whether the database storage is on and whether it encrypts. */
@ApplicationScoped
public class StorageStartup {

    private static final Logger LOG = Logger.getLogger(StorageStartup.class);

    @Inject
    StorageConfig config;

    @Inject
    StorageCrypto crypto;

    void onStart(@Observes StartupEvent event) {
        if (!config.enabled()) {
            LOG.debug("Database storage off: no quarkus.datasource.jdbc.url (static configuration only)");
            return;
        }
        String url = ConfigProvider.getConfig()
            .getOptionalValue(StorageConfigSourceFactory.JDBC_URL, String.class)
            .orElse("(no quarkus.datasource.jdbc.url)");
        LOG.infof("Database storage on: systems, signing keys, secrets and audit events in %s", redact(url));
        if (!crypto.enabled()) {
            LOG.warn("kc-mcp.storage.secret-key is not set: private keys and secrets are stored in plain text");
        }
    }

    /** A JDBC URL without a password that may be embedded in it. */
    static String redact(String url) {
        return url.replaceAll("(?i)(password=)[^;&]*", "$1***");
    }
}
