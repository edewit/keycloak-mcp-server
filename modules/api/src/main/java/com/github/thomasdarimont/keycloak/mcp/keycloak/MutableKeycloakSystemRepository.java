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
     * reconnected by the server on its next use. The settings of its realms are not
     * touched ({@link #saveRealm}): replacing a system keeps them, whatever
     * {@link KeycloakSystem#realms()} holds.
     *
     * @return the system as stored
     */
    KeycloakSystem save(KeycloakSystem system);

    /**
     * Removes a system, and the settings of its realms; false when this repository does
     * not know it.
     */
    boolean delete(String name);

    /**
     * Adds or replaces the settings of one realm of a system this repository holds.
     *
     * @return the settings as stored
     * @throws IllegalArgumentException when the repository does not hold the system
     * @throws UnsupportedOperationException when the repository keeps no realm settings
     */
    default RealmSettings saveRealm(String system, RealmSettings realm) {
        throw new UnsupportedOperationException(id() + " keeps no realm settings");
    }

    /** Removes the settings of one realm; false when there were none. */
    default boolean deleteRealm(String system, String realm) {
        throw new UnsupportedOperationException(id() + " keeps no realm settings");
    }
}
