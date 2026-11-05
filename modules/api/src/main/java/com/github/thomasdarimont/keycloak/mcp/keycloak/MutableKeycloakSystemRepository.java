package com.github.thomasdarimont.keycloak.mcp.keycloak;

/**
 * A {@link KeycloakSystemRepository} that can be written to at runtime: what the admin
 * API and a control plane use to register and remove systems. The server writes to the
 * first mutable repository of its composite (lowest {@link #order()}); the static
 * configuration and the systems file are read-only.
 */
public interface MutableKeycloakSystemRepository extends KeycloakSystemRepository {

    /**
     * Adds or replaces the system of {@link KeycloakSystem#name()}; a replaced system is
     * reconnected by the server on its next use.
     *
     * @return the system as stored
     */
    KeycloakSystem save(KeycloakSystem system);

    /** Removes a system; false when this repository does not know it. */
    boolean delete(String name);
}
