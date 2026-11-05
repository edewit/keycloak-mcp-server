package com.github.thomasdarimont.keycloak.mcp.backend.search;

import java.util.List;
import jakarta.inject.Inject;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;

import io.quarkus.test.junit.QuarkusTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * French queries against the full catalog: the words a French speaking admin would use
 * must land on the right tool without the model translating first.
 */
@QuarkusTest
class FrenchSearchTest {

    @Inject
    ToolCatalog catalog;

    @ParameterizedTest
    @CsvSource({ "déconnecter l'utilisateur, keycloak_user_logout", "deconnecter utilisateur, keycloak_user_logout",
            "désactiver un utilisateur, keycloak_user_set_enabled", "bloquer le compte, keycloak_user_set_enabled",
            "supprimer l'utilisateur, keycloak_user_delete", "supprimez cet utilisateur, keycloak_user_delete",
            "créer un utilisateur, keycloak_user_create", "réinitialiser le mot de passe, keycloak_user_reset_password",
            "changer le mot de passe, keycloak_user_reset_password", "supprimer le groupe, keycloak_group_delete",
            "afficher les membres du groupe, keycloak_group_members_list",
            "quels groupes a l'utilisateur, keycloak_user_groups_list",
            "attribuer un rôle à l'utilisateur, keycloak_user_role_assign",
            "révoquer le rôle de l'utilisateur, keycloak_user_role_unassign", "lister les rôles, keycloak_role_list",
            "rôles de l'application, keycloak_client_roles_list", "lister les organisations, keycloak_org_list",
            "lister les flux d'authentification, keycloak_auth_flows_list",
            "créer un fournisseur d'identité, keycloak_idp_create",
            "lister les fournisseurs d'identité, keycloak_idp_list",
            "synchroniser l'annuaire LDAP, keycloak_federation_sync",
            "sessions de l'utilisateur, keycloak_user_sessions_list",
            "envoyer une invitation par courriel, keycloak_user_send_action_email",
            "afficher les paramètres du domaine, keycloak_realm_get_config",
            "chercher un utilisateur par email, keycloak_user_search", })
    void topHit(String query, String expected) {
        ToolIndex index = new ToolIndex(catalog.all());
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.get(0).spec().name(), query + " -> " + hits);
    }
}
