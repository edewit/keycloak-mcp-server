package com.github.thomasdarimont.keycloak.mcp.oauth;

/**
 * How the server authenticates as an OAuth client at a token endpoint, one
 * {@code token_endpoint_auth_method} (RFC 7591): {@code client_secret_basic},
 * {@code client_secret_post}, {@code private_key_jwt}, ... Independent of the grant: the
 * same authenticator serves a {@code client_credentials} request or any other. Made by a
 * {@link ClientAuthenticatorFactory}; called once per token request, so an authenticator
 * that signs assertions signs a fresh one each time.
 */
@FunctionalInterface
public interface ClientAuthenticator {

    /** Adds the client's credentials to the request (form parameters or headers). */
    void authenticate(TokenRequest request);
}
