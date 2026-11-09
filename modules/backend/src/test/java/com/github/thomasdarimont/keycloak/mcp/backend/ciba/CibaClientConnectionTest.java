package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.client.Client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** One shared client, many polls: connections must go back to the pool. */
class CibaClientConnectionTest {

    private HttpServer server;
    private String issuer;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/demo";
        server.createContext("/realms/demo/.well-known/openid-configuration", x -> {
            byte[] b = ("{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\",\"jwks_uri\":\""
                    + issuer + "/certs\",\"backchannel_authentication_endpoint\":\"" + issuer + "/bc\"}")
                .getBytes(StandardCharsets.UTF_8);
            x.getResponseHeaders().add("Content-Type", "application/json");
            x.sendResponseHeaders(200, b.length);
            try (OutputStream out = x.getResponseBody()) {
                out.write(b);
            }
        });
        server.createContext("/realms/demo/token", x -> {
            x.getRequestBody().readAllBytes();
            byte[] b = "{\"error\":\"authorization_pending\"}".getBytes(StandardCharsets.UTF_8);
            x.getResponseHeaders().add("Content-Type", "application/json");
            x.sendResponseHeaders(400, b.length);
            try (OutputStream out = x.getResponseBody()) {
                out.write(b);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void manyPollsThroughOneClientDoNotExhaustThePool() throws Exception {
        Client shared = OutboundClients.create();
        try {
            CibaClient c = new CibaClient(shared, issuer, "c", "s", "openid");
            for (int i = 0; i < 120; i++) {
                assertEquals(CibaClient.Status.PENDING, c.poll("req").status(), "poll " + i);
            }
            try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<CibaClient.Status>> calls = new ArrayList<>();
                for (int i = 0; i < 80; i++) {
                    calls.add(pool.submit(() -> c.poll("req").status()));
                }
                for (Future<CibaClient.Status> f : calls) {
                    assertEquals(CibaClient.Status.PENDING, f.get(20, TimeUnit.SECONDS));
                }
            }
        }
        finally {
            shared.close();
        }
    }
}
