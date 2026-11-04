package org.keycloak.mcp.catalog;

/**
 * Drives the READ_ONLY filter and the confirmation requirement.
 */
public enum ToolLevel {
    READ, WRITE, DESTRUCTIVE;

    public boolean isWrite() {
        return this != READ;
    }
}
