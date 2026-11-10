package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A tool that declares it only reads cannot write through the admin client. */
class ReadOnlyGuardTest {

    private HttpServer server;
    private String base;
    private Client http;
    private final List<String> received = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", x -> {
            x.getRequestBody().readAllBytes();
            received.add(x.getRequestMethod() + " " + x.getRequestURI().getPath());
            byte[] b = "{}".getBytes(StandardCharsets.UTF_8);
            x.getResponseHeaders().add("Content-Type", "application/json");
            x.sendResponseHeaders(200, b.length);
            try (OutputStream out = x.getResponseBody()) {
                out.write(b);
            }
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        http = OutboundClients.create();
        http.register(new ReadOnlyGuard());
    }

    @AfterEach
    void stop() {
        http.close();
        server.stop(0);
    }

    int get(String path) {
        try (Response r = http.target(base + path).request().get()) {
            return r.getStatus();
        }
    }

    int post(String path) {
        try (Response r = http.target(base + path).request().post(Entity.json("{}"))) {
            return r.getStatus();
        }
    }

    @Test
    void readsPassWritesToTheAdminApiAreRefusedAndRecorded() throws Exception {
        ReadOnlyGuard.Outcome<Integer> outcome = ReadOnlyGuard.run("keycloak_user_get", () -> {
            assertEquals(200, get("/admin/realms/acme/users"));
            assertEquals(200, post("/realms/master/protocol/openid-connect/token"), "token requests pass");
            return post("/admin/realms/acme/users");
        });

        assertEquals(403, outcome.result());
        assertEquals("POST /admin/realms/acme/users", outcome.violation().orElseThrow());
        assertEquals(List.of("GET /admin/realms/acme/users", "POST /realms/master/protocol/openid-connect/token"),
                received, "the write never reached Keycloak");
    }

    @Test
    void aToolThatSwallowsTheRefusalIsStillCaught() throws Exception {
        ReadOnlyGuard.Outcome<String> outcome = ReadOnlyGuard.run("acme_innocent_lookup", () -> {
            try {
                post("/admin/realms/acme/users/1/logout");
            }
            catch (RuntimeException ignored) {
                // a tool hiding what happened
            }
            return "all fine";
        });

        assertTrue(outcome.violation().isPresent());
    }

    @Test
    void outsideAReadOnlyToolNothingIsGuarded() {
        assertEquals(200, post("/admin/realms/acme/users"));
        assertEquals(1, received.size());
    }
}
