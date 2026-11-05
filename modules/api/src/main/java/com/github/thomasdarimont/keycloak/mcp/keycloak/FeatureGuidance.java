package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * How an administrator switches a Keycloak feature on or off. Keycloak has a per-feature
 * option, {@code --feature-<name>=enabled|disabled} (env {@code KC_FEATURE_<NAME>}),
 * which takes precedence over the list options {@code --features} /
 * {@code --features-disabled} ({@code KC_FEATURES} / {@code KC_FEATURES_DISABLED}).
 * Features are build-time options: they are set in the server configuration, on every
 * node, and need a restart. One structured answer for tool results, so the model can
 * quote the right form for the user's deployment instead of guessing.
 *
 * @see <a href="https://www.keycloak.org/server/features">Enabling and disabling
 * features</a>
 */
public final class FeatureGuidance {

    public static final String DOCS = "https://www.keycloak.org/server/features";

    private FeatureGuidance() {
    }

    /** {@code organization} -> {@code KC_FEATURE_ORGANIZATION}. */
    public static String envName(String feature) {
        return "KC_FEATURE_" + ServerCapabilities.normalizeFeature(feature).toUpperCase(Locale.ROOT).replace('-', '_');
    }

    /** One sentence for messages. */
    public static String enableSentence(String feature) {
        String f = ServerCapabilities.normalizeFeature(feature);
        return "An administrator has to enable it in the Keycloak server configuration (" + envName(f)
                + "=enabled or --feature-" + f + "=enabled) on every node and restart Keycloak; see " + DOCS + ".";
    }

    /** The ways to enable a feature, by deployment form. */
    public static Map<String, Object> howToEnable(String feature) {
        return guidance(feature, "enabled");
    }

    /** The ways to disable a feature, by deployment form. */
    public static Map<String, Object> howToDisable(String feature) {
        return guidance(feature, "disabled");
    }

    private static Map<String, Object> guidance(String feature, String state) {
        String f = ServerCapabilities.normalizeFeature(feature);
        String env = envName(f);
        boolean enable = state.equals("enabled");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("feature", f);
        m.put("summary", "Features are server configuration (build options): set the option on every Keycloak node"
                + " and restart. The per-feature option takes precedence over the features / features-disabled lists.");
        m.put("env", env + "=" + state);
        m.put("cli", "bin/kc.sh start --feature-" + f + "=" + state);
        m.put("conf", "feature-" + f + "=" + state + "  (conf/keycloak.conf)");
        m.put("container", "docker run ... -e " + env + "=" + state + " quay.io/keycloak/keycloak start");
        m.put("operator", "spec.features." + state + ": [" + f + "]  (Keycloak CR)");
        m.put("alternative",
                (enable ? "--features=" : "--features-disabled=") + f + " or "
                        + (enable ? "KC_FEATURES=" : "KC_FEATURES_DISABLED=") + f
                        + " (comma separated list; append to features already listed there)");
        m.put("check",
                "keycloak_server_features with name=" + f + " shows the type (preview/experimental features"
                        + " are not supported for production), dependencies and whether it is " + state
                        + " after the restart.");
        m.put("docs", DOCS);
        return m;
    }
}
