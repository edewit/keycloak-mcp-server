package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.UserSessionRepresentation;

/**
 * Compact JSON views of Keycloak representations. Only fields a model needs; nulls
 * omitted.
 */
public final class Views {

    private Views() {
    }

    public static Map<String, Object> user(UserRepresentation u) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "id", u.getId());
        put(m, "username", u.getUsername());
        put(m, "email", u.getEmail());
        put(m, "enabled", u.isEnabled());
        put(m, "firstName", u.getFirstName());
        put(m, "lastName", u.getLastName());
        return m;
    }

    public static Map<String, Object> userDetail(UserRepresentation u) {
        Map<String, Object> m = user(u);
        put(m, "emailVerified", u.isEmailVerified());
        put(m, "createdAt", iso(u.getCreatedTimestamp()));
        put(m, "federationLink", u.getFederationLink());
        if (u.getRequiredActions() != null && !u.getRequiredActions().isEmpty()) {
            m.put("requiredActions", u.getRequiredActions());
        }
        if (u.getAttributes() != null && !u.getAttributes().isEmpty()) {
            Map<String, Object> attrs = new LinkedHashMap<>();
            u.getAttributes().forEach((k, v) -> attrs.put(k, v != null && v.size() == 1 ? v.getFirst() : v));
            m.put("attributes", attrs);
        }
        return m;
    }

    public static Map<String, Object> group(GroupRepresentation g) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "id", g.getId());
        put(m, "name", g.getName());
        put(m, "path", g.getPath());
        if (g.getSubGroupCount() != null && g.getSubGroupCount() > 0) {
            m.put("subGroups", g.getSubGroupCount());
        }
        return m;
    }

    public static Map<String, Object> role(RoleRepresentation r) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "name", r.getName());
        put(m, "description", r.getDescription());
        if (Boolean.TRUE.equals(r.isComposite())) {
            m.put("composite", true);
        }
        if (Boolean.TRUE.equals(r.getClientRole())) {
            m.put("clientRole", true);
        }
        return m;
    }

    public static Map<String, Object> client(ClientRepresentation c) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "id", c.getId());
        put(m, "clientId", c.getClientId());
        put(m, "name", c.getName());
        put(m, "protocol", c.getProtocol());
        put(m, "enabled", c.isEnabled());
        put(m, "publicClient", c.isPublicClient());
        put(m, "serviceAccountsEnabled", c.isServiceAccountsEnabled());
        if (Boolean.TRUE.equals(c.getAuthorizationServicesEnabled())) {
            m.put("authorizationServicesEnabled", true);
        }
        return m;
    }

    public static Map<String, Object> session(UserSessionRepresentation s) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "id", s.getId());
        put(m, "username", s.getUsername());
        put(m, "ipAddress", s.getIpAddress());
        put(m, "start", iso(s.getStart()));
        put(m, "lastAccess", iso(s.getLastAccess()));
        if (s.getClients() != null && !s.getClients().isEmpty()) {
            m.put("clients", new ArrayList<>(s.getClients().values()));
        }
        return m;
    }

    public static <T> List<Map<String, Object>> list(List<T> items, Function<T, Map<String, Object>> f) {
        List<Map<String, Object>> out = new ArrayList<>(items.size());
        for (T t : items) {
            out.add(f.apply(t));
        }
        return out;
    }

    /**
     * {@code {"items":[...],"count":n}} plus {@code "more":true} when the page was full.
     */
    public static Map<String, Object> page(List<Map<String, Object>> items, int max) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("items", items);
        m.put("count", items.size());
        if (items.size() >= max) {
            m.put("more", true);
        }
        return m;
    }

    public static String iso(Long epochMillis) {
        return epochMillis == null ? null : Instant.ofEpochMilli(epochMillis).toString();
    }

    public static void put(Map<String, Object> m, String key, Object value) {
        if (value != null) {
            m.put(key, value);
        }
    }
}
