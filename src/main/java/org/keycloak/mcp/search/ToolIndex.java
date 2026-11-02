package org.keycloak.mcp.search;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import org.keycloak.mcp.catalog.Category;
import org.keycloak.mcp.catalog.ToolSpec;

/**
 * Deterministic lexical index over the tool catalog. See implementation-plan.md §5 for the scoring table.
 */
public class ToolIndex {

    static final int EXACT_NAME = 100;
    static final int FUZZY_NAME = 50;
    static final int NAME_TOKEN = 10;
    static final int TITLE_TOKEN = 6;
    static final int SYNONYM_TOKEN = 6;
    static final int DESCRIPTION_TOKEN = 2;
    static final int PARAM_TOKEN = 2;
    static final int CATEGORY_TOKEN = 4;
    static final int PREFIX_TOKEN = 3;

    private record Doc(ToolSpec spec, Set<String> nameTokens, Set<String> titleTokens, Set<String> synonymTokens,
            Set<String> descriptionTokens, Set<String> paramTokens, Set<String> categoryTokens, String shortName) {
    }

    private final List<Doc> docs = new ArrayList<>();
    private final Map<String, Doc> byName = new HashMap<>();

    public ToolIndex(Collection<ToolSpec> specs) {
        for (ToolSpec spec : specs) {
            String shortName = spec.name().startsWith("keycloak_") ? spec.name().substring(9) : spec.name();
            Doc doc = new Doc(spec,
                    new HashSet<>(Tokenizer.tokens(shortName)),
                    new HashSet<>(Tokenizer.tokens(spec.title())),
                    synonymTokens(spec.synonyms()),
                    new HashSet<>(Tokenizer.tokens(spec.description())),
                    new HashSet<>(Tokenizer.tokens(String.join(" ", spec.parameterNames()))),
                    new HashSet<>(Tokenizer.tokens(spec.category().name() + " " + spec.category().blurb())),
                    shortName);
            docs.add(doc);
            byName.put(spec.name(), doc);
        }
    }

    private static Set<String> synonymTokens(List<String> synonyms) {
        Set<String> out = new HashSet<>();
        for (String s : synonyms) {
            out.addAll(Tokenizer.tokens(s));
        }
        return out;
    }

    public List<SearchHit> search(String query, Category category, int limit, Predicate<ToolSpec> visible) {
        List<String> qTokens = Tokenizer.tokens(query);
        String qName = query == null ? "" : normalizeName(query);
        List<SearchHit> hits = new ArrayList<>();
        for (Doc doc : docs) {
            if (category != null && doc.spec.category() != category) {
                continue;
            }
            if (visible != null && !visible.test(doc.spec)) {
                continue;
            }
            int score = score(doc, qTokens, qName);
            if (score > 0 || (qTokens.isEmpty() && category != null)) {
                hits.add(new SearchHit(doc.spec, score));
            }
        }
        hits.sort(Comparator.comparingInt(SearchHit::score).reversed()
                .thenComparing(h -> h.spec().level())
                .thenComparing(h -> h.spec().name()));
        return hits.size() > limit ? new ArrayList<>(hits.subList(0, limit)) : hits;
    }

    /** Closest tool names for "did you mean" on unknown names. */
    public List<SearchHit> similarNames(String name, int limit, Predicate<ToolSpec> visible) {
        String q = normalizeName(name);
        String qShort = q.startsWith("keycloak_") ? q.substring(9) : q;
        List<SearchHit> hits = new ArrayList<>();
        List<String> qTokens = Tokenizer.tokens(qShort);
        for (Doc doc : docs) {
            if (visible != null && !visible.test(doc.spec)) {
                continue;
            }
            int dist = Fuzzy.distance(qShort, doc.shortName, 4);
            int score = dist <= 4 ? (5 - dist) * 20 : 0;
            for (String t : qTokens) {
                if (doc.nameTokens.contains(t)) {
                    score += NAME_TOKEN;
                } else if (doc.synonymTokens.contains(t) || doc.titleTokens.contains(t)) {
                    score += TITLE_TOKEN;
                }
            }
            if (score > 0) {
                hits.add(new SearchHit(doc.spec, score));
            }
        }
        hits.sort(Comparator.comparingInt(SearchHit::score).reversed().thenComparing(h -> h.spec().name()));
        return hits.size() > limit ? new ArrayList<>(hits.subList(0, limit)) : hits;
    }

    private int score(Doc doc, List<String> qTokens, String qName) {
        int score = 0;
        if (!qName.isEmpty()) {
            if (qName.equals(doc.spec.name()) || qName.equals(doc.shortName)) {
                score += EXACT_NAME;
            } else if (qName.length() >= 6) {
                String qShort = qName.startsWith("keycloak_") ? qName.substring(9) : qName;
                if (Fuzzy.distance(qShort, doc.shortName, 2) <= 2) {
                    score += FUZZY_NAME;
                }
            }
        }
        for (String t : qTokens) {
            boolean matched = false;
            if (doc.nameTokens.contains(t)) {
                score += NAME_TOKEN;
                matched = true;
            }
            if (doc.titleTokens.contains(t)) {
                score += TITLE_TOKEN;
                matched = true;
            }
            if (doc.synonymTokens.contains(t)) {
                score += SYNONYM_TOKEN;
                matched = true;
            }
            if (doc.categoryTokens.contains(t)) {
                score += CATEGORY_TOKEN;
                matched = true;
            }
            if (doc.descriptionTokens.contains(t)) {
                score += DESCRIPTION_TOKEN;
                matched = true;
            }
            if (doc.paramTokens.contains(t)) {
                score += PARAM_TOKEN;
                matched = true;
            }
            if (!matched && t.length() >= 4) {
                // prefix match on name/title tokens: "auth" ~ "authenticator", "fed" ~ "federation"
                for (String nt : doc.nameTokens) {
                    if (nt.startsWith(t) || t.startsWith(nt) && nt.length() >= 4) {
                        score += PREFIX_TOKEN;
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    for (String st : doc.synonymTokens) {
                        if (st.startsWith(t) || t.startsWith(st) && st.length() >= 4) {
                            score += PREFIX_TOKEN;
                            break;
                        }
                    }
                }
            }
        }
        return score;
    }

    private static String normalizeName(String q) {
        return q.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }
}
