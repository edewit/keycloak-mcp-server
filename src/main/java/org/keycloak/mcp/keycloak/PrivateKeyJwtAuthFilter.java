package org.keycloak.mcp.keycloak;

import java.io.IOException;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;

/**
 * Replaces the admin client's placeholder bearer token with one obtained through
 * {@code private_key_jwt}. Runs after the admin client's own filter (default priority)
 * thanks to the higher priority value.
 */
@Priority(Priorities.USER + 1000)
public class PrivateKeyJwtAuthFilter implements ClientRequestFilter, ClientResponseFilter {

    public static final String PLACEHOLDER = "private_key_jwt";

    private final ClientAssertionTokenManager tokens;

    public PrivateKeyJwtAuthFilter(ClientAssertionTokenManager tokens) {
        this.tokens = tokens;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        requestContext.getHeaders().putSingle(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.accessToken());
    }

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) {
        if (responseContext.getStatus() == 401) {
            tokens.invalidate();
        }
    }
}
