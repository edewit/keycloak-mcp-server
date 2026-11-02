package org.keycloak.mcp.guard;

import java.util.List;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.keycloak.mcp.catalog.ToolSpec;
import org.keycloak.mcp.config.McpServerConfig;

/**
 * READ_ONLY and ALLOWED_REALMS. Applied to catalog views, search, execute and registration alike.
 */
@ApplicationScoped
public class AccessPolicy {

    private final boolean readOnly;
    private final Set<String> allowedRealms;

    @Inject
    public AccessPolicy(McpServerConfig config) {
        this(config.readOnly(), config.allowedRealms().orElse(List.of()));
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms) {
        this.readOnly = readOnly;
        this.allowedRealms = allowedRealms == null ? Set.of()
                : Set.copyOf(allowedRealms.stream().map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    public boolean readOnly() {
        return readOnly;
    }

    /** Whether the tool may be listed, searched, registered or executed at all. */
    public boolean permits(ToolSpec spec) {
        return !readOnly || spec.isReadOnly();
    }

    public boolean realmAllowed(String realm) {
        return allowedRealms.isEmpty() || allowedRealms.contains(realm);
    }

    public Set<String> allowedRealms() {
        return allowedRealms;
    }
}
