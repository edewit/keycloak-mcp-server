package org.keycloak.mcp.config;

import java.util.Locale;

/**
 * How the client authenticates at the token endpoint, independent of the {@link GrantType}.
 */
public enum ClientAuth {
    /** {@code client_id} + {@code client_secret} (HTTP basic). */
    CLIENT_SECRET,
    /** Signed JWT client assertion ({@code urn:ietf:params:oauth:client-assertion-type:jwt-bearer}). */
    PRIVATE_KEY_JWT,
    /** Public client, {@code client_id} only. Valid with the password grant (e.g. {@code admin-cli}). */
    NONE;

    public static ClientAuth parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "CLIENT_SECRET", "SECRET", "CLIENT_SECRET_BASIC", "CLIENT_SECRET_POST" -> CLIENT_SECRET;
            case "PRIVATE_KEY_JWT", "JWT", "CLIENT_JWT" -> PRIVATE_KEY_JWT;
            case "NONE", "PUBLIC" -> NONE;
            default -> throw new IllegalArgumentException("Unknown client auth '" + value
                    + "', expected client_secret, private_key_jwt or none");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<ClientAuth> {
        @Override
        public ClientAuth convert(String value) {
            return parse(value);
        }
    }
}
