package org.keycloak.mcp.server.exposure;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Per-connection set of tool names surfaced by the last {@code search_tools} calls
 * (progressive mode only). Bounded so abandoned connections cannot grow it forever.
 */
@ApplicationScoped
public class ProgressiveState {

    private static final int MAX_CONNECTIONS = 1000;
    private static final int MAX_PER_CONNECTION = 24;

    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Set<String>> surfaced = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Set<String>> eldest) {
            return size() > MAX_CONNECTIONS;
        }
    };

    public boolean surface(String connectionId, Collection<String> toolNames) {
        lock.lock();
        try {
            Set<String> set = surfaced.computeIfAbsent(connectionId, k -> new LinkedHashSet<>());
            boolean changed = false;
            for (String n : toolNames) {
                if (set.add(n)) {
                    changed = true;
                }
            }
            while (set.size() > MAX_PER_CONNECTION) {
                String first = set.iterator().next();
                set.remove(first);
                changed = true;
            }
            return changed;
        }
        finally {
            lock.unlock();
        }
    }

    public boolean isSurfaced(String connectionId, String toolName) {
        lock.lock();
        try {
            Set<String> set = surfaced.get(connectionId);
            return set != null && set.contains(toolName);
        }
        finally {
            lock.unlock();
        }
    }

    public void forget(String connectionId) {
        lock.lock();
        try {
            surfaced.remove(connectionId);
        }
        finally {
            lock.unlock();
        }
    }
}
