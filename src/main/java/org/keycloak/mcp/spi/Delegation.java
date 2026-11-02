package org.keycloak.mcp.spi;

/**
 * Whether a tool may run when the server acts on behalf of a caller (delegated access) rather than with its own
 * service account.
 */
public enum Delegation {
    /** Usable with the service account and under delegation (default). */
    ALLOWED,
    /** Never under delegation: the tool exposes secrets or reshapes the realm (e.g. realm_update). */
    FORBIDDEN,
    /** Only under delegation: the action must always be attributable to a human (e.g. a support workflow). */
    REQUIRED
}
