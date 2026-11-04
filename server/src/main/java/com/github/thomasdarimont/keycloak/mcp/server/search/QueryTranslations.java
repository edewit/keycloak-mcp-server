package com.github.thomasdarimont.keycloak.mcp.server.search;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * Query-side translation of non-English search terms into the English vocabulary the tool
 * catalog is written in. Tool names, titles, descriptions and synonyms stay English; a
 * German query such as "Benutzer abmelden" or a French one such as "déconnecter
 * l'utilisateur" is turned into the tokens of "user logout" before scoring.
 * <p>
 * Each {@link Language} has stop words (dropped), a dictionary (folded, lower case, see
 * {@link Tokenizer#fold}: ä -> ae, ß -> ss, é -> e) and inflection rules that map a query
 * word back to a dictionary key (Gruppen -> Gruppe, supprimez -> supprimer). Languages
 * are tried in order; the first dictionary that knows a word wins. Words spelled the same
 * in English (client, realm, token, session, admin, mail, role) need no entry.
 */
final class QueryTranslations {

    private QueryTranslations() {
    }

    /**
     * @param stop words that carry no retrieval signal (articles, pronouns, polite
     * filler)
     * @param words folded word -> English replacement word(s)
     * @param rules suffix -> replacement, tried in order on words of at least four
     * remaining letters
     * @param variants extra spellings to try before giving up (German umlaut plurals)
     */
    record Language(String code, Set<String> stop, Map<String, String> words, List<Rule> rules,
            List<UnaryOperator<String>> variants) {

        record Rule(String suffix, String replacement) {
        }

        String lookup(String word) {
            String hit = words.get(word);
            if (hit != null) {
                return hit;
            }
            for (Rule rule : rules) {
                if (word.length() - rule.suffix().length() >= 4 && word.endsWith(rule.suffix())) {
                    hit = words.get(word.substring(0, word.length() - rule.suffix().length()) + rule.replacement());
                    if (hit != null) {
                        return hit;
                    }
                }
            }
            return null;
        }

        String translate(String folded) {
            String hit = lookup(folded);
            for (int i = 0; hit == null && i < variants.size(); i++) {
                String variant = variants.get(i).apply(folded);
                if (!variant.equals(folded)) {
                    hit = lookup(variant);
                }
            }
            return hit;
        }
    }

    private static List<Language.Rule> strip(String... suffixes) {
        List<Language.Rule> rules = new ArrayList<>();
        for (String s : suffixes) {
            rules.add(new Language.Rule(s, ""));
        }
        return rules;
    }

    // ---- German
    // -------------------------------------------------------------------------------------------------

    private static final Set<String> GERMAN_STOP = Set.of("der", "die", "das", "den", "dem", "des", "ein", "eine",
            "einen", "einem", "einer", "und", "oder", "fuer", "von", "vom", "mit", "im", "am", "um", "zum", "zur", "zu",
            "nach", "bei", "aus", "auf", "ueber", "alle", "allen", "bitte", "zeige", "zeig", "mir", "mich", "ich",
            "will", "moechte", "soll", "sollen", "kann", "koennen", "wie", "welche", "welcher", "welches", "ist",
            "sind", "hat", "haben", "wird", "werden", "noch", "auch", "nicht", "mal", "doch");

    private static final Map<String, String> GERMAN_WORDS = Map.ofEntries(
            // subjects
            Map.entry("benutzer", "user"), Map.entry("benutzerin", "user"), Map.entry("nutzer", "user"),
            Map.entry("anwender", "user"), Map.entry("konto", "user account"), Map.entry("konten", "user account"),
            Map.entry("benutzerkonto", "user account"), Map.entry("person", "user"), Map.entry("mitarbeiter", "user"),
            Map.entry("gruppe", "group"), Map.entry("untergruppe", "subgroup"), Map.entry("mitglied", "member"),
            Map.entry("mitgliedschaft", "membership"), Map.entry("rolle", "role"),
            Map.entry("berechtigung", "permission role"), Map.entry("rechte", "permission role"),
            Map.entry("sitzung", "session"), Map.entry("passwort", "password"), Map.entry("kennwort", "password"),
            Map.entry("identitaetsanbieter", "identity provider"),
            Map.entry("identitaetsprovider", "identity provider"), Map.entry("anbieter", "provider"),
            Map.entry("verbund", "federation"), Map.entry("foederation", "federation"),
            Map.entry("benutzerfoederation", "user federation"), Map.entry("verzeichnis", "directory federation"),
            Map.entry("verzeichnisdienst", "directory ldap"), Map.entry("mandant", "realm"),
            Map.entry("bereich", "realm"), Map.entry("anwendung", "client application"),
            Map.entry("applikation", "client application"), Map.entry("geheimnis", "secret"),
            Map.entry("schluessel", "key"), Map.entry("zertifikat", "certificate"),
            Map.entry("einstellung", "settings config"), Map.entry("konfiguration", "config"),
            Map.entry("ereignis", "event"), Map.entry("protokoll", "event log"),
            Map.entry("anmeldeablauf", "authentication flow"), Map.entry("authentifizierung", "authentication"),
            Map.entry("ablauf", "flow"), Map.entry("organisation", "organization"), Map.entry("geraet", "device"),
            Map.entry("attribut", "attribute"), Map.entry("pflichtaktion", "required action"),
            Map.entry("einladung", "invite"), Map.entry("abteilung", "group department"),
            // verbs / actions
            Map.entry("abmelden", "logout"), Map.entry("ausloggen", "logout"), Map.entry("rauswerfen", "logout kick"),
            Map.entry("anmelden", "login"), Map.entry("einloggen", "login"),
            Map.entry("angemeldet", "logged in online"), Map.entry("eingeloggt", "logged in online"),
            Map.entry("deaktivieren", "disable"), Map.entry("aktivieren", "enable activate"),
            Map.entry("sperren", "disable lock"), Map.entry("entsperren", "enable unlock"),
            Map.entry("loeschen", "delete"), Map.entry("entfernen", "remove"), Map.entry("anlegen", "create"),
            Map.entry("erstellen", "create"), Map.entry("hinzufuegen", "add"),
            Map.entry("registrieren", "register create"), Map.entry("aendern", "change"),
            Map.entry("bearbeiten", "update edit"), Map.entry("umbenennen", "rename"),
            Map.entry("suchen", "search find"), Map.entry("suche", "search find"), Map.entry("finden", "find"),
            Map.entry("anzeigen", "show"), Map.entry("zeigen", "show"), Map.entry("auflisten", "list"),
            Map.entry("liste", "list"), Map.entry("zuweisen", "assign"), Map.entry("zuordnen", "assign"),
            Map.entry("vergeben", "grant assign"), Map.entry("entziehen", "revoke unassign"),
            Map.entry("zuruecksetzen", "reset"), Map.entry("vergessen", "forgot"), Map.entry("bestaetigen", "verify"),
            Map.entry("einladen", "invite"), Map.entry("synchronisieren", "sync"), Map.entry("synchronisation", "sync"),
            Map.entry("abgleichen", "sync"), Map.entry("abgleich", "sync"), Map.entry("importieren", "import"),
            Map.entry("verknuepfen", "link"), Map.entry("trennen", "unlink"), Map.entry("kopieren", "copy"),
            Map.entry("binden", "bind"), Map.entry("wer", "who"), Map.entry("existiert", "exists"),
            Map.entry("gibt", "exists"));

    static final Language GERMAN = new Language("de", GERMAN_STOP, GERMAN_WORDS,
            strip("innen", "en", "er", "es", "e", "n", "s"),
            // umlaut plurals: Abläufe -> Ablauf, Passwörter -> Passwort
            List.of(w -> w.replace("ae", "a").replace("oe", "o").replace("ue", "u")));

    // ---- French
    // -------------------------------------------------------------------------------------------------

    private static final Set<String> FRENCH_STOP = Set.of("le", "la", "les", "l", "un", "une", "du", "de", "des", "d",
            "au", "aux", "et", "ou", "pour", "par", "avec", "sur", "dans", "en", "ce", "cet", "cette", "ces", "qui",
            "que", "quoi", "quel", "quelle", "quels", "quelles", "est", "sont", "ont", "je", "veux", "voudrais",
            "souhaite", "peux", "peut", "mon", "ma", "mes", "son", "ses", "tous", "toutes", "tout", "il", "elle", "ils",
            "elles", "y", "ne", "pas", "merci", "svp", "comment");

    private static final Map<String, String> FRENCH_WORDS = Map.ofEntries(
            // subjects
            Map.entry("utilisateur", "user"), Map.entry("utilisatrice", "user"), Map.entry("usager", "user"),
            Map.entry("compte", "user account"), Map.entry("personne", "user"), Map.entry("employe", "user"),
            Map.entry("collaborateur", "user"), Map.entry("groupe", "group"), Map.entry("sous", "sub"),
            Map.entry("membre", "member"), Map.entry("appartenance", "membership"),
            Map.entry("permission", "permission role"), Map.entry("droit", "permission role"),
            Map.entry("mot", "password"), Map.entry("passe", "password"), Map.entry("fournisseur", "provider"),
            Map.entry("identite", "identity"), Map.entry("annuaire", "directory federation"),
            Map.entry("federation", "federation"), Map.entry("domaine", "realm"), Map.entry("royaume", "realm"),
            Map.entry("application", "client application"), Map.entry("cle", "key"), Map.entry("clef", "key"),
            Map.entry("certificat", "certificate"), Map.entry("parametre", "settings config"),
            Map.entry("reglage", "settings config"), Map.entry("configuration", "config"),
            Map.entry("evenement", "event"), Map.entry("journal", "event log"), Map.entry("flux", "flow"),
            Map.entry("authentification", "authentication"), Map.entry("organisation", "organization"),
            Map.entry("appareil", "device"), Map.entry("attribut", "attribute"), Map.entry("requise", "required"),
            Map.entry("invitation", "invite"), Map.entry("courriel", "email"), Map.entry("portee", "scope"),
            Map.entry("etendue", "scope"), Map.entry("jeton", "token"), Map.entry("connexion", "login"),
            Map.entry("deconnexion", "logout"), Map.entry("secret", "secret"),
            // verbs / actions
            Map.entry("deconnecter", "logout"), Map.entry("connecter", "login"),
            Map.entry("connecte", "logged in online"), Map.entry("desactiver", "disable"),
            Map.entry("desactive", "disabled"), Map.entry("activer", "enable activate"),
            Map.entry("actif", "enabled active"), Map.entry("inactif", "disabled"),
            Map.entry("bloquer", "disable lock"), Map.entry("verrouiller", "disable lock"),
            Map.entry("deverrouiller", "enable unlock"), Map.entry("debloquer", "enable unlock"),
            Map.entry("supprimer", "delete"), Map.entry("effacer", "delete"), Map.entry("retirer", "remove"),
            Map.entry("enlever", "remove"), Map.entry("creer", "create"), Map.entry("ajouter", "add"),
            Map.entry("inscrire", "register create"), Map.entry("modifier", "update change"),
            Map.entry("changer", "change"), Map.entry("editer", "update edit"), Map.entry("mettre", "update"),
            Map.entry("jour", "update"), Map.entry("renommer", "rename"), Map.entry("chercher", "search find"),
            Map.entry("rechercher", "search find"), Map.entry("recherche", "search find"), Map.entry("trouver", "find"),
            Map.entry("afficher", "show"), Map.entry("montrer", "show"), Map.entry("voir", "show"),
            Map.entry("lister", "list"), Map.entry("liste", "list"), Map.entry("attribuer", "assign"),
            Map.entry("assigner", "assign"), Map.entry("accorder", "grant assign"),
            Map.entry("octroyer", "grant assign"), Map.entry("revoquer", "revoke unassign"),
            Map.entry("reinitialiser", "reset"), Map.entry("reinitialisation", "reset"), Map.entry("oublie", "forgot"),
            Map.entry("verifier", "verify"), Map.entry("inviter", "invite"), Map.entry("synchroniser", "sync"),
            Map.entry("synchronisation", "sync"), Map.entry("importer", "import"), Map.entry("lier", "link"),
            Map.entry("associer", "link assign"), Map.entry("delier", "unlink"), Map.entry("dissocier", "unlink"),
            Map.entry("copier", "copy"), Map.entry("envoyer", "send"), Map.entry("existe", "exists"));

    static final Language FRENCH = new Language("fr", FRENCH_STOP, FRENCH_WORDS, List.of(
            // plurals and feminine forms: utilisateurs -> utilisateur, actives -> actif
            // is not attempted
            new Language.Rule("s", ""), new Language.Rule("x", ""),
            // conjugations back to the infinitive: supprimez / suppriment / supprimons /
            // supprime -> supprimer
            new Language.Rule("ez", "er"), new Language.Rule("ent", "er"), new Language.Rule("ons", "er"),
            new Language.Rule("ees", "er"), new Language.Rule("ee", "er"), new Language.Rule("es", "er"),
            new Language.Rule("e", "er")), List.of());

    // ---- all
    // ----------------------------------------------------------------------------------------------------

    static final List<Language> LANGUAGES = List.of(GERMAN, FRENCH);

    /** Stop words of every language; dropped before translation. */
    static final Set<String> STOP;

    static {
        Set<String> all = new LinkedHashSet<>();
        for (Language l : LANGUAGES) {
            all.addAll(l.stop());
        }
        STOP = Set.copyOf(all);
    }

    /**
     * English replacement words for a folded token, or {@code null} when the token is not
     * a known foreign word.
     */
    static List<String> translate(String folded) {
        for (Language language : LANGUAGES) {
            String hit = language.translate(folded);
            if (hit != null) {
                return List.of(hit.split(" "));
            }
        }
        return null;
    }
}
