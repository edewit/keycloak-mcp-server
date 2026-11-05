package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import jakarta.ws.rs.client.Client;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The scope Keycloak 26.8.2+ wants on Admin API tokens is requested by default and
 * dropped when the token endpoint answers {@code invalid_scope} (older servers, strict
 * policies).
 */
class ClientAssertionTokenManagerTest {

    /** A token endpoint that records the form bodies it receives. */
    static final class TokenEndpoint implements AutoCloseable {
        final HttpServer server;
        final List<String> bodies = new ArrayList<>();
        final boolean knowsScope;

        TokenEndpoint(boolean knowsScope) throws IOException {
            this.knowsScope = knowsScope;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String body = URLDecoder.decode(
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8);
                synchronized (bodies) {
                    bodies.add(body);
                }
                boolean withScope = body.contains("scope=");
                byte[] answer = (!knowsScope && withScope
                        ? "{\"error\":\"invalid_scope\",\"error_description\":\"Invalid scopes: kc-admin-api\"}"
                        : "{\"access_token\":\"tok-" + bodies.size() + "\",\"expires_in\":60}")
                    .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(!knowsScope && withScope ? 400 : 200, answer.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(answer);
                }
            });
            server.start();
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    static ClientAssertionTokenManager manager(Client client, String url) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        JwtSigner signer = new JwtSigner(gen.generateKeyPair().getPrivate(), "RS256", null);
        return new ClientAssertionTokenManager(client, url, "master", "mcp", signer, 60, GrantType.CLIENT_CREDENTIALS,
                null, null)
            .scope("kc-admin-api");
    }

    @Test
    void requestsTheScopeAndDropsItWhenTheServerRefusesIt() throws Exception {
        try (TokenEndpoint old = new TokenEndpoint(false); TokenEndpoint current = new TokenEndpoint(true)) {
            Client client = jakarta.ws.rs.client.ClientBuilder.newClient();

            ClientAssertionTokenManager against26_8_1 = manager(client, old.url());
            assertEquals("kc-admin-api", against26_8_1.scope());
            assertEquals("tok-2", against26_8_1.accessToken(), "the retry without the scope succeeds");
            assertEquals(2, old.bodies.size());
            assertTrue(old.bodies.get(0).contains("scope=kc-admin-api"), old.bodies.get(0));
            assertFalse(old.bodies.get(1).contains("scope="), old.bodies.get(1));
            assertNull(against26_8_1.scope(), "refused once, never asked again");
            against26_8_1.invalidate();
            against26_8_1.accessToken();
            assertEquals(3, old.bodies.size());
            assertFalse(old.bodies.get(2).contains("scope="));

            ClientAssertionTokenManager against26_8_2 = manager(client, current.url());
            assertEquals("tok-1", against26_8_2.accessToken());
            assertEquals(1, current.bodies.size());
            assertTrue(current.bodies.get(0).contains("scope=kc-admin-api"), current.bodies.get(0));
            assertEquals("kc-admin-api", against26_8_2.scope());

            assertTrue(ClientAssertionTokenManager.isInvalidScope(400, "{\"error\":\"invalid_scope\"}"));
            assertFalse(ClientAssertionTokenManager.isInvalidScope(401, "{\"error\":\"invalid_scope\"}"));
            assertFalse(ClientAssertionTokenManager.isInvalidScope(400, "{\"error\":\"invalid_client\"}"));
            client.close();
        }
    }
}
