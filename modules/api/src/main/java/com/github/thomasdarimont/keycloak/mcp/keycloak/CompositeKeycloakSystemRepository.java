package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Several repositories as one, ordered by {@link Extension#order()} (lower first, ties by
 * id): names are the union in that order, a lookup takes the first repository that knows
 * the name. A repository that throws is skipped and reported to the failure handler, so
 * one broken registry does not take the others down.
 */
public final class CompositeKeycloakSystemRepository implements KeycloakSystemRepository {

    private final List<KeycloakSystemRepository> repositories;
    private final BiConsumer<KeycloakSystemRepository, RuntimeException> onFailure;

    public CompositeKeycloakSystemRepository(List<KeycloakSystemRepository> repositories) {
        this(repositories, (r, e) -> {
        });
    }

    /** @param onFailure told about a repository that threw during a lookup */
    public CompositeKeycloakSystemRepository(List<KeycloakSystemRepository> repositories,
            BiConsumer<KeycloakSystemRepository, RuntimeException> onFailure) {
        List<KeycloakSystemRepository> sorted = new ArrayList<>(repositories);
        sorted.sort(Comparator.comparingInt(Extension::order).thenComparing(Extension::id));
        this.repositories = List.copyOf(sorted);
        this.onFailure = onFailure;
    }

    @Override
    public String id() {
        return "composite";
    }

    @Override
    public String description() {
        return "systems of " + repositories.stream().map(KeycloakSystemRepository::id).toList();
    }

    /** The aggregated repositories, in lookup order. */
    public List<KeycloakSystemRepository> repositories() {
        return repositories;
    }

    /** The first aggregated repository of a type, e.g. the one to write to. */
    public <T extends KeycloakSystemRepository> Optional<T> repository(Class<T> type) {
        return repositories.stream().filter(type::isInstance).map(type::cast).findFirst();
    }

    @Override
    public List<String> names() {
        Set<String> names = new LinkedHashSet<>();
        for (KeycloakSystemRepository r : repositories) {
            try {
                names.addAll(r.names());
            }
            catch (RuntimeException e) {
                onFailure.accept(r, e);
            }
        }
        return new ArrayList<>(names);
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        for (KeycloakSystemRepository r : repositories) {
            try {
                Optional<KeycloakSystem> found = r.find(name);
                if (found.isPresent()) {
                    return found;
                }
            }
            catch (RuntimeException e) {
                onFailure.accept(r, e);
            }
        }
        return Optional.empty();
    }
}
