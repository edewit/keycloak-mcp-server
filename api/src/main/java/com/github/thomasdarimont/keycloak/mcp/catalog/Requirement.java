package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.keycloak.FeatureGuidance;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

/**
 * What a tool needs from the Keycloak system it runs against: an enabled feature or a
 * minimum version. Checked per call against the system's {@link ServerCapabilities}; an
 * unknown capability never blocks.
 */
public record Requirement(Kind kind, String value) {

    public enum Kind {
        FEATURE, MIN_VERSION, MAX_VERSION
    }

    public Requirement {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(value, "value");
    }

    /**
     * The feature must be enabled, by CLI name ({@code organization}, {@code passkeys}).
     */
    public static Requirement feature(String name) {
        return new Requirement(Kind.FEATURE, ServerCapabilities.normalizeFeature(name));
    }

    /** The server must run this version or newer ({@code 26.8}). */
    public static Requirement minVersion(String version) {
        return new Requirement(Kind.MIN_VERSION, version.trim());
    }

    /**
     * The newest version the tool works with, inclusive at the precision given
     * ({@code 26} covers every 26.x). Unbounded when absent.
     */
    public static Requirement maxVersion(String version) {
        return new Requirement(Kind.MAX_VERSION, version.trim());
    }

    /**
     * Why the requirement is not met, empty when met or when the capability is unknown;
     * the {@link Explanations#ADMINS} wording, which names the configuration to change.
     */
    public Optional<String> unmet(ServerCapabilities caps) {
        return unmet(caps, Explanations.ADMINS);
    }

    /**
     * Why the requirement is not met, worded for the explanations: administrators get the
     * configuration to change, users that it is not available here and that an
     * administrator can change it.
     */
    public Optional<String> unmet(ServerCapabilities caps, Explanations explanations) {
        if (explanations == Explanations.USERS) {
            return plain(caps);
        }
        return switch (kind) {
            case FEATURE -> {
                if (!caps.featuresKnown() || caps.hasFeature(value)) {
                    yield Optional.empty();
                }
                yield Optional.of("needs the Keycloak feature '" + value + "', which is disabled"
                        + (caps.versionKnown() ? " on Keycloak " + caps.version() : "") + ". "
                        + FeatureGuidance.enableSentence(value));
            }
            case MIN_VERSION -> {
                if (!caps.versionKnown() || caps.atLeast(value)) {
                    yield Optional.empty();
                }
                yield Optional.of("needs Keycloak " + value + " or newer; this server runs " + caps.version()
                        + ". An administrator has to upgrade Keycloak.");
            }
            case MAX_VERSION -> {
                if (!caps.versionKnown() || caps.atMost(value)) {
                    yield Optional.empty();
                }
                yield Optional.of("works with Keycloak up to " + value + "; this server runs " + caps.version()
                        + ", which no longer has what the tool relies on. Use the replacement the upgrade notes"
                        + " name.");
            }
        };
    }

    private Optional<String> plain(ServerCapabilities caps) {
        String here = caps.versionKnown() ? " (Keycloak " + caps.version() + ")" : "";
        return switch (kind) {
            case FEATURE -> !caps.featuresKnown() || caps.hasFeature(value) ? Optional.empty()
                    : Optional.of("is not available on this Keycloak server: the '" + value
                            + "' feature is switched off. A Keycloak administrator can enable it.");
            case MIN_VERSION -> !caps.versionKnown() || caps.atLeast(value) ? Optional.empty()
                    : Optional.of("is not available on this Keycloak server" + here + "; it needs Keycloak " + value
                            + " or newer. A Keycloak administrator would have to upgrade.");
            case MAX_VERSION -> !caps.versionKnown() || caps.atMost(value) ? Optional.empty()
                    : Optional.of("is no longer available on this Keycloak server" + here
                            + "; it was removed after Keycloak " + value + ".");
        };
    }

    /**
     * What an administrator does about an unmet requirement: the ways to enable the
     * feature ({@link FeatureGuidance#howToEnable}), or the upgrade note for a version.
     */
    public Map<String, Object> guidance() {
        return switch (kind) {
            case FEATURE -> FeatureGuidance.howToEnable(value);
            case MIN_VERSION -> Map.of("requiredVersion", value, "summary",
                    "Upgrade Keycloak to " + value + " or newer; see https://www.keycloak.org/docs/latest/upgrading/");
            case MAX_VERSION -> Map.of("maxVersion", value, "summary",
                    "The feature or endpoint this tool relies on was removed after Keycloak " + value
                            + "; the upgrade notes name the replacement: https://www.keycloak.org/docs/latest/upgrading/");
        };
    }

    /** {@code feature:organization}, {@code version>=26.8} or {@code version<=26}. */
    public String describe() {
        return switch (kind) {
            case FEATURE -> "feature:" + value;
            case MIN_VERSION -> "version>=" + value;
            case MAX_VERSION -> "version<=" + value;
        };
    }
}
