package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryKeycloakSystemRepositoryTest {

    @Test
    void namesAndLookupsStayConsistentUnderConcurrentWritesFromVirtualThreads() throws Exception {
        InMemoryKeycloakSystemRepository repo = new InMemoryKeycloakSystemRepository("t", 0,
                List.of(DynamicSystemsTest.system("fixed", "https://fixed.example.com")));
        int writers = 32;
        int rounds = 200;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger inconsistencies = new AtomicInteger();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> tasks = new ArrayList<>();
            for (int w = 0; w < writers; w++) {
                String name = "sys-" + (w % 4);
                tasks.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < rounds; i++) {
                        repo.put(DynamicSystemsTest.system(name, "https://" + name + "-" + i + ".example.com"));
                        repo.remove(name);
                    }
                    return null;
                }));
            }
            for (int r = 0; r < 8; r++) {
                tasks.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < rounds * 4; i++) {
                        // every listed name must be findable in the same snapshot's terms
                        for (String n : repo.names()) {
                            Optional<KeycloakSystem> s = repo.find(n);
                            if (s.isPresent() && !s.get().name().equals(n)) {
                                inconsistencies.incrementAndGet();
                            }
                        }
                        if (repo.find("fixed").isEmpty()) {
                            inconsistencies.incrementAndGet();
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> t : tasks) {
                t.get(60, TimeUnit.SECONDS);
            }
        }
        assertEquals(0, inconsistencies.get());
        assertEquals(List.of("fixed"), repo.names(), "every put was followed by its remove");
        assertTrue(repo.all().stream().map(KeycloakSystem::name).allMatch(Set.of("fixed")::contains));
    }

    @Test
    void putKeepsPositionAndRemoveReportsWhatItRemoved() {
        InMemoryKeycloakSystemRepository repo = new InMemoryKeycloakSystemRepository();
        repo.put(DynamicSystemsTest.system("a", "http://a"));
        repo.put(DynamicSystemsTest.system("b", "http://b"));
        repo.put(DynamicSystemsTest.system("a", "http://a2"));
        assertEquals(List.of("a", "b"), repo.names());
        assertEquals("http://a2", repo.find("a").orElseThrow().url());
        assertEquals("http://b", repo.remove("b").orElseThrow().url());
        assertTrue(repo.remove("b").isEmpty());
        assertEquals(List.of("a"), repo.names());
        assertEquals("in-memory", repo.id());
    }
}
