package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns {@code --name=value} command line arguments into configuration properties. Only
 * this server's and Quarkus' own settings are accepted, so that a mistyped option is
 * refused instead of becoming a property nobody reads. JVM options such as {@code -Dname}
 * are not arguments and are not checked.
 */
final class ConfigArguments {

    private ConfigArguments() {
    }

    /**
     * @throws IllegalArgumentException for anything that is not a setting
     */
    static Map<String, String> parse(List<String> arguments) {
        Map<String, String> properties = new LinkedHashMap<>();
        for (String argument : arguments) {
            int equals = argument.indexOf('=');
            String name = argument.substring(0, equals < 0 ? argument.length() : equals);
            if (!name.startsWith("--kc-mcp.") && !name.startsWith("--quarkus.")) {
                throw new IllegalArgumentException("Unknown option: '" + argument
                        + "'. Settings are --kc-mcp.<name>=<value> or --quarkus.<name>=<value>.");
            }
            if (equals < 0) {
                throw new IllegalArgumentException(name + " needs a value, as " + name + "=<value>");
            }
            String property = name.substring(2);
            if (!OptionCatalogue.known(property)) {
                throw new IllegalArgumentException(OptionCatalogue.describe(property));
            }
            properties.put(property, argument.substring(equals + 1));
        }
        return properties;
    }
}
