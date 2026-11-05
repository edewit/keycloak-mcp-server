package com.github.thomasdarimont.keycloak.mcp.server.spi;

import com.github.thomasdarimont.keycloak.mcp.spi.AuditListener;

/**
 * Not registered on the class path: {@link ExtensionsTest} names it in the service file
 * of a jar in a providers directory.
 */
public class JarOnlyListener implements AuditListener {

    @Override
    public void onToolCall(Event event) {
    }
}
