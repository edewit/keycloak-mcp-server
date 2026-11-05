package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What an MCP entry is bound to: requests that arrive through {@code /mcp/s/<system>} or
 * {@code /mcp/s/<system>/<realm>} carry this binding, and every call on that connection
 * is bound to it. Arguments that disagree are refused.
 *
 * @param system the system, never {@code null}
 * @param realm the realm, {@code null} when the entry is bound to a system only
 */
public record EntryBinding(String system, String realm) {

    /** Key of the binding in the Vert.x routing context. */
    public static final String KEY = "kc-mcp.entry";

    public EntryBinding {
        if (system == null || system.isBlank()) {
            throw new IllegalArgumentException("A binding needs a system");
        }
        realm = realm == null || realm.isBlank() ? null : realm;
    }

    public String describe() {
        return realm == null ? "system '" + system + "'" : "system '" + system + "', realm '" + realm + "'";
    }

    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("system", system);
        if (realm != null) {
            m.put("realm", realm);
        }
        return m;
    }
}
