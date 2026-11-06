package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Which hosts the server may talk to ({@code kc-mcp.allowed-hosts}): every configured
 * Keycloak URL must match one pattern, checked at startup. A pattern is
 * {@code [scheme://]host[:port]} where {@code *} in the host matches any run of
 * characters: {@code *.example.com}, {@code https://sso-*.corp.example.com},
 * {@code localhost:8080}. Comparison is case-insensitive; a pattern without scheme or
 * port accepts any. Empty = no restriction.
 */
public final class HostAllowList {

    public static final HostAllowList ANY = new HostAllowList(List.of());

    private record Rule(String text, String scheme, Pattern host, Integer port, boolean literal) {
        boolean matches(URI uri) {
            if (scheme != null && !scheme.equalsIgnoreCase(uri.getScheme())) {
                return false;
            }
            if (port != null && port != effectivePort(uri)) {
                return false;
            }
            String h = uri.getHost();
            return h != null && host.matcher(h.toLowerCase(Locale.ROOT)).matches();
        }
    }

    private final List<Rule> rules;

    private HostAllowList(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    /** Parses the patterns; blank entries are ignored, none at all means {@link #ANY}. */
    public static HostAllowList of(List<String> patterns) {
        List<Rule> rules = new ArrayList<>();
        for (String p : patterns == null ? List.<String>of() : patterns) {
            String t = p.trim();
            if (!t.isEmpty()) {
                rules.add(parse(t));
            }
        }
        return rules.isEmpty() ? ANY : new HostAllowList(rules);
    }

    public boolean unrestricted() {
        return rules.isEmpty();
    }

    public List<String> patterns() {
        return rules.stream().map(Rule::text).toList();
    }

    /** Whether the URL's scheme, host and port match one of the patterns. */
    public boolean permits(String url) {
        if (rules.isEmpty()) {
            return true;
        }
        return matching(url, false);
    }

    /**
     * Whether a pattern without a wildcard in the host names the URL's host (and matches
     * its scheme and port when it has them); {@code false} for an unrestricted list.
     */
    public boolean namesLiterally(String url) {
        return matching(url, true);
    }

    private boolean matching(String url, boolean literalOnly) {
        URI uri;
        try {
            uri = URI.create(url.trim());
        }
        catch (IllegalArgumentException e) {
            return false;
        }
        for (Rule r : rules) {
            if ((!literalOnly || r.literal()) && r.matches(uri)) {
                return true;
            }
        }
        return false;
    }

    private static Rule parse(String pattern) {
        String rest = pattern;
        String scheme = null;
        int sep = rest.indexOf("://");
        if (sep > 0) {
            scheme = rest.substring(0, sep).toLowerCase(Locale.ROOT);
            rest = rest.substring(sep + 3);
        }
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            rest = rest.substring(0, slash);
        }
        Integer port = null;
        int colon = rest.lastIndexOf(':');
        if (colon >= 0 && !rest.startsWith("[")) {
            String p = rest.substring(colon + 1);
            if (p.chars().allMatch(Character::isDigit) && !p.isEmpty()) {
                port = Integer.parseInt(p);
                rest = rest.substring(0, colon);
            }
        }
        if (rest.isEmpty()) {
            throw new IllegalArgumentException("Host pattern '" + pattern + "' has no host");
        }
        StringBuilder regex = new StringBuilder();
        for (String part : rest.toLowerCase(Locale.ROOT).split("\\*", -1)) {
            if (!regex.isEmpty()) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(part));
        }
        return new Rule(pattern, scheme, Pattern.compile(regex.toString()), port, rest.indexOf('*') < 0);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : "http".equalsIgnoreCase(uri.getScheme()) ? 80 : -1;
    }
}
