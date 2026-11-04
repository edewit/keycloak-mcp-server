package com.github.thomasdarimont.keycloak.mcp.server.search;

import java.util.List;
import jakarta.inject.Inject;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.github.thomasdarimont.keycloak.mcp.server.catalog.ToolCatalog;

import io.quarkus.test.junit.QuarkusTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * German queries against the full catalog: the words a German speaking admin would use
 * must land on the right tool without the model translating first.
 */
@QuarkusTest
class GermanSearchTest {

    @Inject
    ToolCatalog catalog;

    @ParameterizedTest
    @CsvSource({ "Benutzer abmelden, keycloak_user_logout", "find user by email, keycloak_user_search",
            "list identity providers, keycloak_idp_list", "assign role to user, keycloak_user_role_assign",
            "Nutzer ausloggen, keycloak_user_logout", "Benutzer deaktivieren, keycloak_user_set_enabled",
            "Konto sperren, keycloak_user_set_enabled", "Benutzer löschen, keycloak_user_delete",
            "Benutzer loeschen, keycloak_user_delete", "Benutzer anlegen, keycloak_user_create",
            "Passwort zurücksetzen, keycloak_user_reset_password", "Kennwort ändern, keycloak_user_reset_password",
            "Gruppe löschen, keycloak_group_delete", "Mitglieder der Gruppe anzeigen, keycloak_group_members_list",
            "Welche Gruppen hat der Benutzer, keycloak_user_groups_list",
            "Rolle dem Benutzer zuweisen, keycloak_user_role_assign",
            "Benutzer die Rolle entziehen, keycloak_user_role_unassign", "Rollen auflisten, keycloak_role_list",
            "Rollen der Anwendung auflisten, keycloak_client_roles_list", "Organisationen auflisten, keycloak_org_list",
            "Anmeldeabläufe auflisten, keycloak_auth_flows_list", "Identitätsanbieter anlegen, keycloak_idp_create",
            "Identitätsanbieter auflisten, keycloak_idp_list", "LDAP Verzeichnis abgleichen, keycloak_federation_sync",
            "Benutzerföderation synchronisieren, keycloak_federation_sync",
            "Sitzungen des Benutzers, keycloak_user_sessions_list",
            "Einladung per E-Mail senden, keycloak_user_send_action_email",
            "Mandant Einstellungen anzeigen, keycloak_realm_get_config", })
    void topHit(String query, String expected) {
        ToolIndex index = new ToolIndex(catalog.all());
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.get(0).spec().name(), query + " -> " + hits);
    }
}
