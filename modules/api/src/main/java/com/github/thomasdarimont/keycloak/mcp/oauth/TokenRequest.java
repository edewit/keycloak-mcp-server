package com.github.thomasdarimont.keycloak.mcp.oauth;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A request to an OAuth token endpoint while it is being built: the form parameters and
 * headers it will carry. The grant fills in its own parameters ({@code grant_type},
 * {@code scope}), the {@link ClientAuthenticator} adds how the client authenticates.
 */
public final class TokenRequest {

    private final URI tokenEndpoint;
    private final Map<String, String> form = new LinkedHashMap<>();
    private final Map<String, String> headers = new LinkedHashMap<>();

    public TokenRequest(URI tokenEndpoint) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    }

    public URI tokenEndpoint() {
        return tokenEndpoint;
    }

    /** Sets a form parameter; {@code null} removes it. */
    public TokenRequest param(String name, String value) {
        if (value == null) {
            form.remove(name);
        }
        else {
            form.put(name, value);
        }
        return this;
    }

    /** Sets a header; {@code null} removes it. */
    public TokenRequest header(String name, String value) {
        if (value == null) {
            headers.remove(name);
        }
        else {
            headers.put(name, value);
        }
        return this;
    }

    public Map<String, String> form() {
        return Collections.unmodifiableMap(form);
    }

    public Map<String, String> headers() {
        return Collections.unmodifiableMap(headers);
    }

    /** Never prints parameter values, which carry secrets and assertions. */
    @Override
    public String toString() {
        return "TokenRequest[" + tokenEndpoint + ", params=" + form.keySet() + ", headers=" + headers.keySet() + "]";
    }
}
