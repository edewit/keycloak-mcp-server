package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * OAuth 2 grant used to obtain the admin access token.
 */
public enum GrantType {
    /** Service account of a confidential client. Default. */
    CLIENT_CREDENTIALS("client_credentials"),
    /** Resource owner password of an admin user; local development only. */
    PASSWORD("password");

    private final String oauthValue;

    GrantType(String oauthValue) {
        this.oauthValue = oauthValue;
    }

    public String oauthValue() {
        return oauthValue;
    }

    public static GrantType parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "CLIENT_CREDENTIALS" -> CLIENT_CREDENTIALS;
            case "PASSWORD" -> PASSWORD;
            default -> throw new IllegalArgumentException(
                    "Unknown grant type '" + value + "', expected client_credentials or password");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<GrantType> {
        @Override
        public GrantType convert(String value) {
            return parse(value);
        }
    }
}
