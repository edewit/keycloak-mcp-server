package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessages;

/**
 * The texts of the configuration specs and problems, from the message bundles of the
 * server and of every extension jar, the providers directory included.
 */
@ApplicationScoped
public class ConfigMessagesProducer {

    @Produces
    @ApplicationScoped
    ConfigMessages configMessages(Extensions extensions) {
        return new ConfigMessages(extensions.classLoader());
    }
}
