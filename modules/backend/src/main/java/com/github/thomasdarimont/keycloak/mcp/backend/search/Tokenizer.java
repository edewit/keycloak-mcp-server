package com.github.thomasdarimont.keycloak.mcp.backend.search;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Lower-case, fold accents and umlauts, split on non-alphanumerics and camelCase, drop
 * stop words, translate known German and French words into their English equivalents
 * ({@link QueryTranslations}), light suffix stripping.
 */
public final class Tokenizer {

    private static final Set<String> STOP = Set.of("a", "an", "the", "of", "to", "in", "for", "and", "or", "by", "with",
            "from", "on", "is", "all", "this", "that", "me", "my", "please", "show", "get", "keycloak");

    /**
     * Abbreviations used in tool names for phrases that titles and queries spell out
     * (stemmed form -> alias). The alias is added next to the phrase so "list identity
     * providers" reaches {@code idp_list} by name token.
     */
    private static final Map<List<String>, String> ALIASES = Map.of(List.of("identity", "provider"), "idp",
            List.of("provider", "identity"), "idp", // French word order: fournisseur
                                                    // d'identité
            List.of("organization"), "org", List.of("authentication"), "auth");

    /**
     * Verbs that mean the same thing for this catalog: a request to "list users" wants
     * {@code user_search}, "find clients" wants {@code client_list}. Mapped to one token
     * after stemming so that name tokens match either way.
     */
    private static final Map<String, String> CANONICAL = Map.of("list", "find", "search", "find", "lookup", "find",
            "look", "find", "query", "find");

    private Tokenizer() {
    }

    public static List<String> tokens(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        String spaced = text.replaceAll("([a-z0-9])([A-Z])", "$1 $2");
        String[] parts = fold(spaced).split("[^a-z0-9]+");
        Set<String> out = new LinkedHashSet<>();
        for (String p : parts) {
            // single letters carry no meaning and come from possessives ("user's" ->
            // "user", "s")
            if (p.length() < 2 || STOP.contains(p) || QueryTranslations.STOP.contains(p)) {
                continue;
            }
            List<String> translated = QueryTranslations.translate(p);
            if (translated != null) {
                for (String t : translated) {
                    out.add(canonical(stem(t)));
                }
            }
            else {
                out.add(canonical(stem(p)));
            }
        }
        List<String> tokens = new ArrayList<>(out);
        ALIASES.forEach((phrase, alias) -> {
            if (Collections.indexOfSubList(tokens, phrase) >= 0 && !tokens.contains(alias)) {
                tokens.add(alias);
            }
        });
        return tokens;
    }

    /**
     * Lower case with German umlauts and ß written out (ä -> ae, ö -> oe, ü -> ue, ß ->
     * ss, the usual ASCII transcription) and every other diacritic stripped (é -> e), so
     * that "löschen", "loeschen" and "Identität" survive the alphanumeric split as single
     * words.
     */
    public static String fold(String text) {
        String lower = text.toLowerCase(Locale.ROOT)
            .replace("ä", "ae")
            .replace("ö", "oe")
            .replace("ü", "ue")
            .replace("ß", "ss");
        String decomposed = Normalizer.normalize(lower, Normalizer.Form.NFD);
        return decomposed.replaceAll("\\p{M}+", "");
    }

    /** The catalog's one verb for listing, searching and looking things up. */
    public static String canonical(String stemmed) {
        return CANONICAL.getOrDefault(stemmed, stemmed);
    }

    /**
     * Very light stemming: users -> user, listing -> list, enabled -> enabl(e), groups ->
     * group.
     */
    public static String stem(String word) {
        String w = word;
        if (w.length() > 4 && w.endsWith("ing")) {
            w = w.substring(0, w.length() - 3);
        }
        else if (w.length() > 4 && w.endsWith("ies")) {
            w = w.substring(0, w.length() - 3) + "y";
        }
        else if (w.length() > 3 && w.endsWith("ed")) {
            w = w.substring(0, w.length() - 2);
        }
        else if (w.length() > 3 && w.endsWith("es") && !w.endsWith("ses")) {
            w = w.substring(0, w.length() - 1);
        }
        if (w.length() > 3 && w.endsWith("s") && !w.endsWith("ss")) {
            w = w.substring(0, w.length() - 1);
        }
        if (w.length() > 4 && w.endsWith("e")) {
            w = w.substring(0, w.length() - 1);
        }
        return w;
    }
}
