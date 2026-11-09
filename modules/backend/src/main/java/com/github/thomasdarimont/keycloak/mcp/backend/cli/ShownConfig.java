package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.ConfigProvider;

import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.smallrye.config.ConfigValue;
import io.smallrye.config.SmallRyeConfig;

/** How {@code show-config} presents the effective configuration. */
final class ShownConfig {

    static final String MASK = "*******";
    private static final String QUARKUS_PREFIX = "quarkus.";
    private static final String SPI_PREFIX = "kc-mcp.spi.";
    // header lists carry credentials in their value, as Authorization=Bearer ...
    private static final Pattern SECRET = Pattern
        .compile("password|secret|token|credential|(^|-)key$|private|(^|-)headers$|^\"?authorization\"?$");
    private static final Pattern URL_PASSWORD = Pattern.compile("(?i)(password=)[^;&]*");

    private ShownConfig() {
    }

    static void print(boolean all, java.io.PrintWriter out) {
        SmallRyeConfig config = ConfigProvider.getConfig().unwrap(SmallRyeConfig.class);
        TreeSet<String> names = new TreeSet<>();
        config.getPropertyNames().forEach(names::add);
        out.println("Built for database: " + builtDatabase(config));
        out.println("Configuration:");
        names.stream().filter(n -> n.startsWith(OptionCatalogue.PREFIX)).forEach(n -> printProperty(config, n, out));
        if (all) {
            out.println("Quarkus configuration:");
            names.stream().filter(n -> n.startsWith(QUARKUS_PREFIX)).forEach(n -> printProperty(config, n, out));
        }
    }

    /**
     * Before Quarkus starts, the configuration holds the kind of the Maven build; the
     * {@code build} command leaves a note when it has changed that.
     */
    private static String builtDatabase(SmallRyeConfig config) {
        String home = System.getProperty("kcmcp.home.dir");
        if (home != null) {
            try {
                return Files.readString(Path.of(home, "lib", "quarkus", "db-kind")).trim();
            }
            catch (IOException e) {
                // no build command has run here
            }
        }
        return config.getConfigValue("quarkus.datasource.db-kind").getValue();
    }

    private static void printProperty(SmallRyeConfig config, String name, java.io.PrintWriter out) {
        ConfigValue value;
        try {
            value = config.getConfigValue(name);
        }
        catch (RuntimeException e) {
            out.printf("  %s = <invalid: %s>%n", name, ValidationRun.message(e));
            return;
        }
        if (value.getValue() == null) {
            return;
        }
        out.printf("  %s = %s (%s)%n", name, mask(name, value.getValue()), source(value.getConfigSourceName()));
    }

    /**
     * Masks by name, on the side of caution. Every {@code kc-mcp.spi.*} value is masked:
     * extensions define those keys, so nothing says which of them are secret.
     */
    static String mask(String name, String value) {
        String last = name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT);
        if (name.startsWith(SPI_PREFIX) || SECRET.matcher(last).find()) {
            return MASK;
        }
        return URL_PASSWORD.matcher(value).replaceAll("$1" + MASK);
    }

    private static String source(String name) {
        if (name == null) {
            return "default";
        }
        if (name.startsWith("SysPropConfigSource")) {
            return "command line";
        }
        if (name.startsWith("EnvConfigSource")) {
            return "environment";
        }
        if (name.contains("kc-mcp.config-files")) {
            return "configuration file";
        }
        if (name.startsWith("PropertiesConfigSource[source=jar:")) {
            return "built-in default";
        }
        return name;
    }
}
