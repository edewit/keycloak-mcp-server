package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.nio.file.Path;
import java.util.Optional;

/**
 * The directory the distribution was unpacked to, which {@code bin/kcmcp.sh} and
 * {@code bin/kcmcp.bat} pass as the system property {@value #PROPERTY}. Absent when the
 * server runs without the scripts: from the build, in a container, in tests.
 */
public record DistributionHome(Path directory) {

    public static final String PROPERTY = "kcmcp.home.dir";

    private static final String EXPRESSION = "${" + PROPERTY + "}";

    /** The home of this JVM, if it was started from a distribution. */
    public static Optional<DistributionHome> current() {
        return of(System.getProperty(PROPERTY));
    }

    static Optional<DistributionHome> of(String directory) {
        return Optional.ofNullable(directory).filter(d -> !d.isBlank()).map(d -> new DistributionHome(Path.of(d)));
    }

    /** A path below the home directory. */
    public Path resolve(String first, String... more) {
        return directory.resolve(Path.of(first, more));
    }

    /** The value with {@code ${kcmcp.home.dir}} replaced by this directory. */
    public String expand(String value) {
        return value.replace(EXPRESSION, directory.toString());
    }
}
