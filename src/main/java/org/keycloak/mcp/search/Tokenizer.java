package org.keycloak.mcp.search;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Lower-case, split on non-alphanumerics and camelCase, drop stop words, light suffix stripping.
 */
public final class Tokenizer {

    private static final Set<String> STOP = Set.of("a", "an", "the", "of", "to", "in", "for", "and", "or", "by",
            "with", "from", "on", "is", "all", "this", "that", "me", "my", "please", "show", "get", "keycloak");

    private Tokenizer() {
    }

    public static List<String> tokens(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        String spaced = text.replaceAll("([a-z0-9])([A-Z])", "$1 $2");
        String[] parts = spaced.toLowerCase(Locale.ROOT).split("[^a-z0-9]+");
        Set<String> out = new LinkedHashSet<>();
        for (String p : parts) {
            if (p.isEmpty() || STOP.contains(p)) {
                continue;
            }
            out.add(stem(p));
        }
        return new ArrayList<>(out);
    }

    /** Very light stemming: users -> user, listing -> list, enabled -> enabl(e), groups -> group. */
    public static String stem(String word) {
        String w = word;
        if (w.length() > 4 && w.endsWith("ing")) {
            w = w.substring(0, w.length() - 3);
        } else if (w.length() > 4 && w.endsWith("ies")) {
            w = w.substring(0, w.length() - 3) + "y";
        } else if (w.length() > 3 && w.endsWith("ed")) {
            w = w.substring(0, w.length() - 2);
        } else if (w.length() > 3 && w.endsWith("es") && !w.endsWith("ses")) {
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
