package org.keycloak.mcp.server.keycloak;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.mcp.keycloak.KeycloakAdmin;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

/**
 * Resolves the effective roles of a user or group <em>with provenance</em>: direct,
 * inherited from a group (or a parent group), or expanded from a composite. The realm's
 * {@code default-roles-<realm>} composite and the roles reachable only through it are
 * reported separately so they do not drown the interesting ones.
 */
public final class EffectiveRoles {

    /** Realm role names map to themselves, client roles to {@code <clientId>.<role>}. */
    private final Map<String, Set<String>> sources = new TreeMap<>();
    private final Set<String> onlyViaDefaults = new TreeSet<>();
    private final Set<String> directRealm = new TreeSet<>();
    private final Map<String, Set<String>> directClient = new TreeMap<>();
    private final List<String> groups = new ArrayList<>();
    private final KeycloakAdmin kc;
    private final String realm;
    private final String defaultRole;
    private final Map<String, String> clientIdByUuid = new HashMap<>();

    private record Seed(RoleRepresentation role, String source, boolean viaDefaults) {
    }

    private EffectiveRoles(KeycloakAdmin kc, String realm) {
        this.kc = kc;
        this.realm = realm;
        this.defaultRole = "default-roles-" + realm.toLowerCase();
    }

    public static EffectiveRoles ofUser(KeycloakAdmin kc, String realm, String userId) {
        EffectiveRoles r = new EffectiveRoles(kc, realm);
        RealmResource rr = kc.realm(realm);
        List<Seed> seeds = new ArrayList<>();
        r.collect(rr.users().get(userId).roles(), "direct", seeds, true);
        for (GroupRepresentation g : rr.users().get(userId).groups(0, 500, true)) {
            r.groups.add(g.getPath());
            r.collectGroupChain(g.getPath(), seeds);
        }
        r.expand(seeds);
        return r;
    }

    public static EffectiveRoles ofGroup(KeycloakAdmin kc, String realm, String groupPath) {
        EffectiveRoles r = new EffectiveRoles(kc, realm);
        List<Seed> seeds = new ArrayList<>();
        r.collectGroupChain(groupPath, seeds);
        r.expand(seeds);
        return r;
    }

    private void collectGroupChain(String path, List<Seed> seeds) {
        RealmResource rr = kc.realm(realm);
        for (String p : ancestorPaths(path)) {
            try {
                GroupRepresentation g = rr.getGroupByPath(p);
                collect(rr.groups().group(g.getId()).roles(), "group:" + p, seeds, false);
            }
            catch (WebApplicationException e) {
                // unreadable ancestor: skip
            }
        }
    }

    private void collect(RoleMappingResource mappings, String source, List<Seed> seeds, boolean recordDirect) {
        MappingsRepresentation all = mappings.getAll();
        if (all.getRealmMappings() != null) {
            for (RoleRepresentation role : all.getRealmMappings()) {
                boolean isDefault = role.getName().equals(defaultRole);
                seeds.add(new Seed(role, source, isDefault));
                if (recordDirect && !isDefault) {
                    directRealm.add(role.getName());
                }
            }
        }
        if (all.getClientMappings() != null) {
            for (ClientMappingsRepresentation cm : all.getClientMappings().values()) {
                for (RoleRepresentation role : cm.getMappings()) {
                    seeds.add(new Seed(role, source, false));
                    if (recordDirect) {
                        directClient.computeIfAbsent(cm.getClient(), k -> new TreeSet<>()).add(role.getName());
                    }
                }
            }
        }
    }

    private void expand(List<Seed> seeds) {
        Deque<Seed> queue = new ArrayDeque<>(seeds);
        Map<String, Boolean> seen = new HashMap<>(); // role id -> reached via non-default
                                                     // path
        while (!queue.isEmpty()) {
            Seed s = queue.poll();
            RoleRepresentation role = s.role();
            if (role == null || role.getId() == null) {
                continue;
            }
            String key = key(role);
            if (!role.getName().equals(defaultRole)) {
                sources.computeIfAbsent(key, k -> new TreeSet<>()).add(s.source());
                if (s.viaDefaults()) {
                    onlyViaDefaults.add(key);
                }
            }
            Boolean before = seen.get(role.getId());
            boolean nonDefault = !s.viaDefaults();
            if (before != null && (before || !nonDefault)) {
                continue; // already expanded with at least as strong a path
            }
            seen.put(role.getId(), nonDefault || Boolean.TRUE.equals(before));
            if (nonDefault) {
                onlyViaDefaults.remove(key);
            }
            if (role.isComposite()) {
                try {
                    for (RoleRepresentation child : kc.realm(realm).rolesById().getRoleComposites(role.getId())) {
                        boolean childViaDefaults = s.viaDefaults() || role.getName().equals(defaultRole);
                        queue.add(new Seed(child, "composite:" + role.getName(), childViaDefaults));
                    }
                }
                catch (WebApplicationException e) {
                    // composites unreadable: keep what we have
                }
            }
        }
        // a role reached both via defaults and via a real path is not "only via defaults"
        for (Map.Entry<String, Set<String>> e : sources.entrySet()) {
            boolean realPath = e.getValue()
                .stream()
                .anyMatch(src -> !src.equals("composite:" + defaultRole) && !isDefaultDescendant(src));
            if (realPath) {
                onlyViaDefaults.remove(e.getKey());
            }
        }
    }

    private boolean isDefaultDescendant(String source) {
        if (!source.startsWith("composite:")) {
            return false;
        }
        String parent = source.substring("composite:".length());
        return onlyViaDefaults.contains(parent);
    }

    private String key(RoleRepresentation role) {
        if (Boolean.TRUE.equals(role.getClientRole())) {
            String clientId = clientIdByUuid.computeIfAbsent(role.getContainerId(), uuid -> {
                try {
                    return kc.realm(realm).clients().get(uuid).toRepresentation().getClientId();
                }
                catch (WebApplicationException e) {
                    return uuid;
                }
            });
            return clientId + "." + role.getName();
        }
        return role.getName();
    }

    static List<String> ancestorPaths(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (String p : path.split("/")) {
            if (!p.isEmpty()) {
                sb.append('/').append(p);
                out.add(sb.toString());
            }
        }
        return out;
    }

    // ---- views
    // --------------------------------------------------------------------------------------------------

    public Set<String> directRealmRoles() {
        return directRealm;
    }

    public Map<String, Set<String>> directClientRoles() {
        return directClient;
    }

    public List<String> groups() {
        return groups;
    }

    /**
     * Effective realm roles without the realm's default composite and its exclusive
     * members.
     */
    public Set<String> effectiveRealmRoles() {
        Set<String> out = new TreeSet<>();
        for (String k : sources.keySet()) {
            if (!k.contains(".") && !onlyViaDefaults.contains(k)) {
                out.add(k);
            }
        }
        return out;
    }

    /** Effective client roles per client, same exclusion. */
    public Map<String, Set<String>> effectiveClientRoles() {
        Map<String, Set<String>> out = new TreeMap<>();
        for (String k : sources.keySet()) {
            int dot = k.lastIndexOf('.');
            if (dot > 0 && !onlyViaDefaults.contains(k)) {
                out.computeIfAbsent(k.substring(0, dot), c -> new TreeSet<>()).add(k.substring(dot + 1));
            }
        }
        return out;
    }

    /**
     * Roles every user has through {@code default-roles-<realm>} (realm and client
     * roles).
     */
    public Set<String> defaultRoles() {
        return new TreeSet<>(onlyViaDefaults);
    }

    /**
     * Where each effective role comes from: {@code direct}, {@code group:/path},
     * {@code composite:<role>}.
     */
    public Map<String, List<String>> sources() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : sources.entrySet()) {
            if (!onlyViaDefaults.contains(e.getKey())) {
                out.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
        }
        return out;
    }

    /** Compact JSON for tool results. */
    public Map<String, Object> toView(boolean includeDirect) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (includeDirect) {
            m.put("realmRoles", new ArrayList<>(directRealm));
            if (!directClient.isEmpty()) {
                m.put("clientRoles", directClient);
            }
        }
        m.put("effectiveRealmRoles", new ArrayList<>(effectiveRealmRoles()));
        Map<String, Set<String>> ec = effectiveClientRoles();
        if (!ec.isEmpty()) {
            m.put("effectiveClientRoles", ec);
        }
        if (!groups.isEmpty()) {
            m.put("groups", groups);
        }
        m.put("sources", sources());
        Set<String> defaults = defaultRoles();
        if (!defaults.isEmpty()) {
            m.put("defaultRoles", new ArrayList<>(defaults));
        }
        return m;
    }

    static Set<String> set(Set<String> s) {
        return new HashSet<>(s);
    }
}
