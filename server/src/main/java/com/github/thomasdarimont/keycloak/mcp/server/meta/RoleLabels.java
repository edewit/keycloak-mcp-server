package com.github.thomasdarimont.keycloak.mcp.server.meta;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.spi.GrantedRoles;

/**
 * Human readable labels for Keycloak's {@code realm-management} roles (the wording of the
 * admin console) in the languages a {@code whoami} answer may be asked in, plus the
 * coarse "what may I do per area" summary derived from them. Unknown roles and
 * unsupported languages fall back to the role name / English, so the model can still
 * translate on its own.
 */
final class RoleLabels {

    private RoleLabels() {
    }

    static final String DEFAULT_LANGUAGE = "en";

    private static final Map<String, String> EN = Map.ofEntries(
            Map.entry("realm-admin", "Realm admin (everything in this realm)"), Map.entry("view-realm", "View realm"),
            Map.entry("manage-realm", "Manage realm"), Map.entry("query-realms", "Query realms"),
            Map.entry("view-users", "View users"), Map.entry("manage-users", "Manage users"),
            Map.entry("query-users", "Query users"), Map.entry("query-groups", "Query groups"),
            Map.entry("view-clients", "View clients"), Map.entry("manage-clients", "Manage clients"),
            Map.entry("query-clients", "Query clients"), Map.entry("create-client", "Create clients"),
            Map.entry("view-identity-providers", "View identity providers"),
            Map.entry("manage-identity-providers", "Manage identity providers"),
            Map.entry("view-events", "View events"), Map.entry("manage-events", "Manage events"),
            Map.entry("view-authorization", "View authorization"),
            Map.entry("manage-authorization", "Manage authorization"), Map.entry("impersonation", "Impersonate users"),
            Map.entry("admin", "Server admin (all realms)"), Map.entry("create-realm", "Create realms"));

    private static final Map<String, String> DE = Map.ofEntries(
            Map.entry("realm-admin", "Realm-Administrator (alles in diesem Realm)"),
            Map.entry("view-realm", "Realm anzeigen"), Map.entry("manage-realm", "Realm verwalten"),
            Map.entry("query-realms", "Realms abfragen"), Map.entry("view-users", "Benutzer anzeigen"),
            Map.entry("manage-users", "Benutzer verwalten"), Map.entry("query-users", "Benutzer abfragen"),
            Map.entry("query-groups", "Gruppen abfragen"), Map.entry("view-clients", "Clients anzeigen"),
            Map.entry("manage-clients", "Clients verwalten"), Map.entry("query-clients", "Clients abfragen"),
            Map.entry("create-client", "Clients anlegen"),
            Map.entry("view-identity-providers", "Identity Provider anzeigen"),
            Map.entry("manage-identity-providers", "Identity Provider verwalten"),
            Map.entry("view-events", "Ereignisse anzeigen"), Map.entry("manage-events", "Ereignisse verwalten"),
            Map.entry("view-authorization", "Autorisierung anzeigen"),
            Map.entry("manage-authorization", "Autorisierung verwalten"),
            Map.entry("impersonation", "Benutzer impersonieren"),
            Map.entry("admin", "Server-Administrator (alle Realms)"), Map.entry("create-realm", "Realms anlegen"));

    private static final Map<String, Map<String, String>> LANGUAGES = Map.of("en", EN, "de", DE);

    /**
     * Area name -> the realm-management roles that grant manage / view / query access to
     * it.
     */
    record Area(String name, String manage, String view, String query) {
    }

    static final List<Area> AREAS = List.of(new Area("users", "manage-users", "view-users", "query-users"),
            new Area("groups", "manage-users", "view-users", "query-groups"),
            new Area("clients", "manage-clients", "view-clients", "query-clients"),
            new Area("realm", "manage-realm", "view-realm", "query-realms"),
            new Area("identityProviders", "manage-identity-providers", "view-identity-providers", null),
            new Area("events", "manage-events", "view-events", null),
            new Area("authorization", "manage-authorization", "view-authorization", null));

    /** {@code de-DE} -> {@code de}; unsupported or blank -> {@code en}. */
    static String language(String requested) {
        if (requested == null || requested.isBlank()) {
            return DEFAULT_LANGUAGE;
        }
        String lang = requested.trim().toLowerCase(Locale.ROOT);
        int cut = lang.indexOf('-');
        if (cut < 0) {
            cut = lang.indexOf('_');
        }
        if (cut > 0) {
            lang = lang.substring(0, cut);
        }
        return LANGUAGES.containsKey(lang) ? lang : DEFAULT_LANGUAGE;
    }

    static String label(String role, String language) {
        Map<String, String> table = LANGUAGES.getOrDefault(language, EN);
        String l = table.get(role);
        return l != null ? l : EN.getOrDefault(role, role);
    }

    /** {@code users -> manage | view | query | none} for one realm. */
    static Map<String, String> capabilities(GrantedRoles granted, String realm) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Area a : AREAS) {
            String level = "none";
            if (granted.holds(realm, a.manage())) {
                level = "manage";
            }
            else if (granted.holds(realm, a.view())) {
                level = "view";
            }
            else if (a.query() != null && granted.holds(realm, a.query())) {
                level = "query";
            }
            out.put(a.name(), level);
        }
        return out;
    }
}
