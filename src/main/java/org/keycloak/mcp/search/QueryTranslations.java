package org.keycloak.mcp.search;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Query-side translation of non-English search terms into the English vocabulary the tool catalog is written in.
 * Tool names, titles, descriptions and synonyms stay English; a German query such as "Benutzer abmelden" is turned
 * into the tokens of "user logout" before scoring. Keys are folded ({@link Tokenizer#fold}: ä -> ae, ß -> ss),
 * lower case and looked up exactly first, then with common German inflection suffixes stripped
 * (Gruppen -> Gruppe, Benutzern -> Benutzer). Words that are spelled the same in English (client, realm, token,
 * session, admin, mail) need no entry.
 */
final class QueryTranslations {

    private QueryTranslations() {
    }

    /** German words that carry no retrieval signal (articles, pronouns, polite filler). */
    static final Set<String> STOP = Set.of("der", "die", "das", "den", "dem", "des", "ein", "eine", "einen", "einem",
            "einer", "und", "oder", "fuer", "von", "vom", "mit", "im", "am", "um", "zum", "zur", "zu", "nach", "bei",
            "aus", "auf", "ueber", "alle", "allen", "bitte", "zeige", "zeig", "mir", "mich", "ich", "will", "moechte",
            "soll", "sollen", "kann", "koennen", "wie", "welche", "welcher", "welches", "ist", "sind", "hat", "haben",
            "wird", "werden", "noch", "auch", "nicht", "mal", "doch");

    private static final Map<String, String> GERMAN = Map.ofEntries(
            // subjects
            Map.entry("benutzer", "user"),
            Map.entry("benutzerin", "user"),
            Map.entry("nutzer", "user"),
            Map.entry("anwender", "user"),
            Map.entry("konto", "user account"),
            Map.entry("konten", "user account"),
            Map.entry("benutzerkonto", "user account"),
            Map.entry("person", "user"),
            Map.entry("mitarbeiter", "user"),
            Map.entry("gruppe", "group"),
            Map.entry("untergruppe", "subgroup"),
            Map.entry("mitglied", "member"),
            Map.entry("mitgliedschaft", "membership"),
            Map.entry("rolle", "role"),
            Map.entry("berechtigung", "permission role"),
            Map.entry("rechte", "permission role"),
            Map.entry("sitzung", "session"),
            Map.entry("passwort", "password"),
            Map.entry("kennwort", "password"),
            Map.entry("identitaetsanbieter", "identity provider"),
            Map.entry("identitaetsprovider", "identity provider"),
            Map.entry("anbieter", "provider"),
            Map.entry("verbund", "federation"),
            Map.entry("foederation", "federation"),
            Map.entry("benutzerfoederation", "user federation"),
            Map.entry("verzeichnis", "directory federation"),
            Map.entry("verzeichnisdienst", "directory ldap"),
            Map.entry("mandant", "realm"),
            Map.entry("bereich", "realm"),
            Map.entry("anwendung", "client application"),
            Map.entry("applikation", "client application"),
            Map.entry("geheimnis", "secret"),
            Map.entry("schluessel", "key"),
            Map.entry("zertifikat", "certificate"),
            Map.entry("einstellung", "settings config"),
            Map.entry("konfiguration", "config"),
            Map.entry("ereignis", "event"),
            Map.entry("protokoll", "event log"),
            Map.entry("anmeldeablauf", "authentication flow"),
            Map.entry("authentifizierung", "authentication"),
            Map.entry("ablauf", "flow"),
            Map.entry("organisation", "organization"),
            Map.entry("geraet", "device"),
            Map.entry("attribut", "attribute"),
            Map.entry("pflichtaktion", "required action"),
            Map.entry("einladung", "invite"),
            Map.entry("abteilung", "group department"),
            // verbs / actions
            Map.entry("abmelden", "logout"),
            Map.entry("ausloggen", "logout"),
            Map.entry("rauswerfen", "logout kick"),
            Map.entry("anmelden", "login"),
            Map.entry("einloggen", "login"),
            Map.entry("angemeldet", "logged in online"),
            Map.entry("eingeloggt", "logged in online"),
            Map.entry("deaktivieren", "disable"),
            Map.entry("aktivieren", "enable activate"),
            Map.entry("sperren", "disable lock"),
            Map.entry("entsperren", "enable unlock"),
            Map.entry("loeschen", "delete"),
            Map.entry("entfernen", "remove"),
            Map.entry("anlegen", "create"),
            Map.entry("erstellen", "create"),
            Map.entry("hinzufuegen", "add"),
            Map.entry("registrieren", "register create"),
            Map.entry("aendern", "change"),
            Map.entry("bearbeiten", "update edit"),
            Map.entry("umbenennen", "rename"),
            Map.entry("suchen", "search find"),
            Map.entry("suche", "search find"),
            Map.entry("finden", "find"),
            Map.entry("anzeigen", "show"),
            Map.entry("zeigen", "show"),
            Map.entry("auflisten", "list"),
            Map.entry("liste", "list"),
            Map.entry("zuweisen", "assign"),
            Map.entry("zuordnen", "assign"),
            Map.entry("vergeben", "grant assign"),
            Map.entry("entziehen", "revoke unassign"),
            Map.entry("zuruecksetzen", "reset"),
            Map.entry("vergessen", "forgot"),
            Map.entry("bestaetigen", "verify"),
            Map.entry("einladen", "invite"),
            Map.entry("synchronisieren", "sync"),
            Map.entry("synchronisation", "sync"),
            Map.entry("abgleichen", "sync"),
            Map.entry("abgleich", "sync"),
            Map.entry("importieren", "import"),
            Map.entry("verknuepfen", "link"),
            Map.entry("trennen", "unlink"),
            Map.entry("kopieren", "copy"),
            Map.entry("binden", "bind"),
            Map.entry("wer", "who"),
            Map.entry("existiert", "exists"),
            Map.entry("gibt", "exists"));

    private static final String[] SUFFIXES = { "innen", "en", "er", "es", "e", "n", "s" };

    /** English replacement words for a folded token, or {@code null} when the token is not a known foreign word. */
    static List<String> translate(String folded) {
        String hit = lookup(folded);
        if (hit == null && (folded.contains("ae") || folded.contains("oe") || folded.contains("ue"))) {
            // umlaut plurals: Abläufe -> Ablauf, Passwörter -> Passwort
            hit = lookup(folded.replace("ae", "a").replace("oe", "o").replace("ue", "u"));
        }
        return hit == null ? null : List.of(hit.split(" "));
    }

    private static String lookup(String word) {
        String hit = GERMAN.get(word);
        if (hit != null) {
            return hit;
        }
        for (String suffix : SUFFIXES) {
            if (word.length() - suffix.length() >= 4 && word.endsWith(suffix)) {
                hit = GERMAN.get(word.substring(0, word.length() - suffix.length()));
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }
}
