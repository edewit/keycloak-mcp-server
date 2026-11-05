package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;

/**
 * Not registered on the class path: {@link ExtensionsTest} names it in the service file
 * of a jar in a providers directory.
 */
public class JarOnlyListener implements AuditListener {

    @Override
    public void onToolCall(Event event) {
    }
}
