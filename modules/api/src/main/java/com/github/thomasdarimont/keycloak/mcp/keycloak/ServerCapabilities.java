package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.keycloak.representations.info.FeatureRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;

/**
 * What a Keycloak system can do: its version and the enabled features, read from the
 * admin server info or configured ({@code kc-mcp.systems.<name>.version}).
 * {@link #UNKNOWN} when neither is available; checks against unknown capabilities pass.
 *
 * @param version the server version ({@code 26.8.2}), {@code null} when unknown
 * @param features enabled features by their CLI name ({@code organization},
 * {@code passkeys}), empty when unknown
 * @param featuresKnown whether {@code features} was read from the server
 */
public record ServerCapabilities(String version, Set<String> features, boolean featuresKnown) {

    public static final ServerCapabilities UNKNOWN = new ServerCapabilities(null, Set.of(), false);

    public ServerCapabilities {
        version = version == null || version.isBlank() ? null : version.trim();
        Set<String> normalized = new TreeSet<>();
        for (String f : features == null ? Set.<String>of() : features) {
            normalized.add(normalizeFeature(f));
        }
        features = Set.copyOf(new LinkedHashSet<>(normalized));
    }

    /** Version and enabled features of a server info document. */
    public static ServerCapabilities of(ServerInfoRepresentation info) {
        if (info == null) {
            return UNKNOWN;
        }
        String version = info.getSystemInfo() == null ? null : info.getSystemInfo().getVersion();
        Set<String> enabled = new TreeSet<>();
        if (info.getFeatures() != null) {
            for (FeatureRepresentation f : info.getFeatures()) {
                if (f.isEnabled() && f.getName() != null) {
                    enabled.add(f.getName());
                }
            }
        }
        return new ServerCapabilities(version, enabled, info.getFeatures() != null);
    }

    /** The same capabilities with another version, e.g. the configured one. */
    public ServerCapabilities withVersion(String newVersion) {
        return new ServerCapabilities(newVersion, features, featuresKnown);
    }

    public boolean versionKnown() {
        return version != null;
    }

    /** Whether the feature is enabled; {@code false} when the features are unknown. */
    public boolean hasFeature(String name) {
        return features.contains(normalizeFeature(name));
    }

    /**
     * Whether the version is at least {@code minimum} (numeric segments compared, a
     * qualifier such as {@code -SNAPSHOT} ignored); {@code false} when unknown.
     */
    public boolean atLeast(String minimum) {
        return version != null && compareVersions(version, minimum) >= 0;
    }

    /**
     * Whether the version is at most {@code maximum}, inclusive at the precision given:
     * {@code atMost("26")} accepts 26.8.2, {@code atMost("26.8")} accepts 26.8.3 but not
     * 26.9.0; {@code false} when unknown.
     */
    public boolean atMost(String maximum) {
        if (version == null) {
            return false;
        }
        int[] max = segments(maximum);
        int[] own = segments(version);
        for (int i = 0; i < max.length; i++) {
            int o = i < own.length ? own[i] : 0;
            if (o != max[i]) {
                return o < max[i];
            }
        }
        return true;
    }

    /**
     * {@code ORGANIZATION}, {@code Organizations} and {@code organization} compare alike.
     */
    public static String normalizeFeature(String name) {
        Objects.requireNonNull(name, "name");
        return name.trim().toLowerCase(Locale.ROOT).replace('_', '-').replace(' ', '-');
    }

    /** Numeric segment comparison: {@code 26.10.0 > 26.8.2}, {@code 26.8 == 26.8.0}. */
    public static int compareVersions(String a, String b) {
        int[] x = segments(a);
        int[] y = segments(b);
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int xi = i < x.length ? x[i] : 0;
            int yi = i < y.length ? y[i] : 0;
            if (xi != yi) {
                return Integer.compare(xi, yi);
            }
        }
        return 0;
    }

    private static int[] segments(String version) {
        String core = version.trim();
        int cut = core.indexOf('-');
        if (cut >= 0) {
            core = core.substring(0, cut);
        }
        String[] parts = core.split("\\.");
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String digits = parts[i].replaceAll("[^0-9].*$", "");
            out[i] = digits.isEmpty() ? 0 : Integer.parseInt(digits);
        }
        return out;
    }

    @Override
    public String toString() {
        return version == null ? "unknown" : version + (featuresKnown ? " " + features : "");
    }
}
