package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Systems held in memory: the static configuration at startup, systems added at runtime,
 * tests. Copy-on-write: readers see one immutable snapshot and never block, writers
 * replace it under a {@link ReentrantLock} (no {@code synchronized}, so virtual threads
 * are not pinned). {@link #put} replaces a system of the same name, which reconnects it
 * on the next lookup; names keep their insertion order.
 */
public class InMemoryKeycloakSystemRepository implements KeycloakSystemRepository {

    private final String id;
    private final int order;
    private final ReentrantLock writes = new ReentrantLock();
    private volatile Map<String, KeycloakSystem> snapshot = Map.of();

    public InMemoryKeycloakSystemRepository() {
        this("in-memory", 0, List.of());
    }

    public InMemoryKeycloakSystemRepository(List<KeycloakSystem> initial) {
        this("in-memory", 0, initial);
    }

    public InMemoryKeycloakSystemRepository(String id, List<KeycloakSystem> initial) {
        this(id, 0, initial);
    }

    /** @param order position among the repositories of a composite, lower first */
    public InMemoryKeycloakSystemRepository(String id, int order, List<KeycloakSystem> initial) {
        this.id = id;
        this.order = order;
        Map<String, KeycloakSystem> seed = new LinkedHashMap<>();
        for (KeycloakSystem s : initial) {
            seed.put(s.name(), s);
        }
        this.snapshot = Collections.unmodifiableMap(seed);
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public int order() {
        return order;
    }

    @Override
    public String description() {
        return "systems held in memory";
    }

    @Override
    public List<String> names() {
        return List.copyOf(snapshot.keySet());
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        return Optional.ofNullable(snapshot.get(name));
    }

    @Override
    public List<KeycloakSystem> all() {
        return List.copyOf(snapshot.values());
    }

    /** Adds or replaces a system; a known name keeps its position. */
    public void put(KeycloakSystem system) {
        writes.lock();
        try {
            Map<String, KeycloakSystem> next = new LinkedHashMap<>(snapshot);
            next.put(system.name(), system);
            snapshot = Collections.unmodifiableMap(next);
        }
        finally {
            writes.unlock();
        }
    }

    /** Removes a system; the one removed, empty when unknown. */
    public Optional<KeycloakSystem> remove(String name) {
        writes.lock();
        try {
            if (!snapshot.containsKey(name)) {
                return Optional.empty();
            }
            Map<String, KeycloakSystem> next = new LinkedHashMap<>(snapshot);
            KeycloakSystem removed = next.remove(name);
            snapshot = Collections.unmodifiableMap(next);
            return Optional.ofNullable(removed);
        }
        finally {
            writes.unlock();
        }
    }

    public boolean isEmpty() {
        return snapshot.isEmpty();
    }
}
