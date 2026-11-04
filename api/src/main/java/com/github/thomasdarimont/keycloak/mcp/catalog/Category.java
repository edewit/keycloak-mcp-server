package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.Locale;

/**
 * Tool areas. The blurb is shown by {@code search_tools} when called without a query.
 */
public enum Category {
    USERS("Find, create, update, enable/disable, delete users; passwords, action emails, role mappings"),
    GROUPS("Groups, group membership and group role mappings"), ROLES("Realm roles and client roles"),
    CLIENTS("OIDC/SAML clients: list, create, update, delete, secrets, mappers, client roles"),
    CLIENT_SCOPES("Client scopes and their assignment to clients"),
    IDP("Identity providers (Google, GitHub, SAML, OIDC brokers) and their mappers"),
    ORGS("Organizations (tenants) and their identity provider links"),
    FEDERATION("User federation providers (LDAP, Active Directory, Kerberos) and sync"),
    AUTH_FLOWS("Authentication flows, executions, required actions, authenticator providers"),
    EVENTS("Login events and admin events"), REALM("Realm configuration, SMTP, WebAuthn, server info"),
    SESSIONS("User sessions and logout");

    private final String blurb;

    Category(String blurb) {
        this.blurb = blurb;
    }

    public String blurb() {
        return blurb;
    }

    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Category parse(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        for (Category c : values()) {
            if (c.name().equals(v)) {
                return c;
            }
        }
        // a few forgiving aliases
        return switch (v) {
            case "USER" -> USERS;
            case "GROUP" -> GROUPS;
            case "ROLE" -> ROLES;
            case "CLIENT" -> CLIENTS;
            case "SCOPES", "CLIENT_SCOPE" -> CLIENT_SCOPES;
            case "IDPS", "IDENTITY_PROVIDERS", "IDENTITY_PROVIDER" -> IDP;
            case "ORG", "ORGANIZATIONS", "ORGANIZATION" -> ORGS;
            case "LDAP", "USER_FEDERATION" -> FEDERATION;
            case "AUTH", "AUTHENTICATION", "FLOWS", "AUTH_FLOW" -> AUTH_FLOWS;
            case "EVENT" -> EVENTS;
            case "REALMS" -> REALM;
            case "SESSION" -> SESSIONS;
            default -> null;
        };
    }
}
