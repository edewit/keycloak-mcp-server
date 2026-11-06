package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

import org.jboss.resteasy.reactive.client.api.QuarkusRestClientProperties;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;

/**
 * JAX-RS clients for the server's own outbound calls outside the Keycloak admin client
 * (CIBA, the UI's discovery and session checks): Quarkus REST's implementation, as the
 * admin client uses, so filters, timeouts and TLS work the same everywhere. Timeouts come
 * from {@code kc-mcp.http.connect-timeout} / {@code read-timeout}, overridable per
 * client. A named {@code quarkus.tls.<name>.*} configuration supplies the trust store for
 * a provider behind a private CA (its trust store; client certificates are not supported
 * here); without one the JVM's default trust applies. Redirects are not followed (the
 * implementation's default).
 */
public final class OutboundClients {

    /** Connect and read timeout of a client. */
    public record Timeouts(Duration connect, Duration read) {

        /** As {@code kc-mcp.http.*} defaults: 10 s to connect, 60 s to read. */
        public static final Timeouts DEFAULT = new Timeouts(Duration.ofSeconds(10), Duration.ofSeconds(60));

        public Timeouts {
            connect = positive(connect, "connect");
            read = positive(read, "read");
        }

        /** The global {@code kc-mcp.http.*} values. */
        public static Timeouts of(McpServerConfig config) {
            return new Timeouts(config.http().connectTimeout(), config.http().readTimeout());
        }

        /** These timeouts with the given overrides where present. */
        public Timeouts with(Optional<Duration> connectOverride, Optional<Duration> readOverride) {
            return new Timeouts(connectOverride.orElse(connect), readOverride.orElse(read));
        }

        private static Duration positive(Duration d, String which) {
            if (d == null || d.isNegative() || d.isZero()) {
                throw new IllegalArgumentException("The " + which + " timeout must be positive, not " + d);
            }
            return d;
        }
    }

    private OutboundClients() {
    }

    /** A client with the default timeouts and trust. */
    public static Client create() {
        return create(Timeouts.DEFAULT);
    }

    /** A client with the default trust. */
    public static Client create(Timeouts timeouts) {
        return builder(timeouts).build();
    }

    /**
     * {@link #create(Timeouts, String, TlsConfigurationRegistry, String)} with the
     * default timeouts.
     */
    public static Client create(String tlsConfigurationName, TlsConfigurationRegistry registry, String setting) {
        return create(Timeouts.DEFAULT, tlsConfigurationName, registry, setting);
    }

    /**
     * A client whose TLS comes from the named configuration of the registry.
     *
     * @param tlsConfigurationName {@code null} or blank for the default trust
     * @param setting the property that named it, for the error message
     * @throws IllegalStateException when the name is unknown or has no trust store
     */
    public static Client create(Timeouts timeouts, String tlsConfigurationName, TlsConfigurationRegistry registry,
            String setting) {
        if (tlsConfigurationName == null || tlsConfigurationName.isBlank()) {
            return create(timeouts);
        }
        if (registry == null) {
            throw new IllegalStateException(setting + "=" + tlsConfigurationName + " needs the TLS registry");
        }
        TlsConfiguration tls = registry.get(tlsConfigurationName)
            .orElseThrow(() -> new IllegalStateException(setting + "=" + tlsConfigurationName
                    + " names no TLS configuration: define quarkus.tls." + tlsConfigurationName + ".trust-store.*"));
        // Quarkus REST's ClientBuilder takes key stores, not an SSLContext
        ClientBuilder b = builder(timeouts);
        if (tls.isTrustAll()) {
            if (b instanceof org.jboss.resteasy.reactive.client.impl.ClientBuilderImpl impl) {
                impl.trustAll(true);
            }
            b.hostnameVerifier((host, session) -> true);
        }
        else if (tls.getTrustStore() != null) {
            b.trustStore(tls.getTrustStore());
        }
        else {
            throw new IllegalStateException("TLS configuration '" + tlsConfigurationName + "' (" + setting
                    + ") has no trust store: set quarkus.tls." + tlsConfigurationName + ".trust-store.*");
        }
        if (tls.getHostnameVerificationAlgorithm().filter("NONE"::equalsIgnoreCase).isPresent()) {
            b.hostnameVerifier((host, session) -> true);
        }
        return b.build();
    }

    /**
     * Applies the read timeout to a client that was built elsewhere (the Keycloak admin
     * client's provider): Quarkus REST honors it per request. The connect timeout is
     * fixed when a client is built and stays the provider's.
     */
    public static Client readTimeout(Client client, Duration read) {
        client.property(QuarkusRestClientProperties.READ_TIMEOUT, read.toMillis());
        return client;
    }

    /**
     * A duration setting of an extension ({@code kc-mcp.spi.<id>.*}, plain strings):
     * {@code 10s}, {@code 500ms}, {@code PT10S}, or a number of seconds.
     */
    public static Optional<Duration> duration(Optional<String> value, String setting) {
        return value.filter(v -> !v.isBlank()).map(v -> {
            try {
                return com.github.thomasdarimont.keycloak.mcp.config.Durations.parse(v);
            }
            catch (RuntimeException e) {
                throw new IllegalArgumentException(setting + " is not a duration: '" + v + "' (e.g. 10s, 500ms, PT1M)");
            }
        });
    }

    private static ClientBuilder builder(Timeouts t) {
        return ClientBuilder.newBuilder()
            .connectTimeout(t.connect().toMillis(), TimeUnit.MILLISECONDS)
            .readTimeout(t.read().toMillis(), TimeUnit.MILLISECONDS);
    }
}
