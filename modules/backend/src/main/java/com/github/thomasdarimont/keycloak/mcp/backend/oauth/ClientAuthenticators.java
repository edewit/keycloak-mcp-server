package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeSet;

import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticator;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticatorFactory;

/**
 * The {@link ClientAuthenticatorFactory}s by method id. The first factory of an id wins,
 * so a list that puts the extensions' factories first lets them replace a built-in one.
 */
public final class ClientAuthenticators {

    private final Map<String, ClientAuthenticatorFactory> byId = new LinkedHashMap<>();

    public ClientAuthenticators(List<ClientAuthenticatorFactory> factories) {
        for (ClientAuthenticatorFactory f : factories) {
            byId.putIfAbsent(normalize(f.id()), f);
        }
    }

    /** The factories on the class path, for tests and callers without CDI. */
    public static ClientAuthenticators fromClassPath() {
        return new ClientAuthenticators(
                ServiceLoader.load(ClientAuthenticatorFactory.class, ClientAuthenticators.class.getClassLoader())
                    .stream()
                    .map(ServiceLoader.Provider::get)
                    .toList());
    }

    /**
     * An authenticator of the named method.
     *
     * @throws IllegalStateException when no factory serves the method, or the method's
     * settings are incomplete
     */
    public ClientAuthenticator create(String method, ClientAuthenticatorFactory.Context context) {
        ClientAuthenticatorFactory f = byId.get(normalize(method));
        if (f == null) {
            throw new IllegalStateException(context.settingPrefix() + "client-auth=" + method
                    + " is not a known client authentication method; known: " + new TreeSet<>(byId.keySet()));
        }
        return f.create(context);
    }

    /**
     * {@code private-key-jwt} and {@code PRIVATE_KEY_JWT} name {@code private_key_jwt}.
     */
    static String normalize(String id) {
        return id.trim().toLowerCase(Locale.ROOT).replace('-', '_');
    }
}
