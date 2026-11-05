/**
 * What extensions of the Keycloak MCP server compile against: the SPI, the tool catalog
 * types, the configuration interface and the admin client facade. The server itself is a
 * Quarkus application and runs on the class path, so this is the only module descriptor.
 * <p>
 * The Keycloak client jars declare no module name, so their automatic names
 * ({@code keycloak.admin.client}, {@code keycloak.client.common.synced}) are derived from
 * the file names and may change with a Keycloak upgrade.
 */
module com.github.thomasdarimont.keycloak.mcp.api {

    exports com.github.thomasdarimont.keycloak.mcp.catalog;

    exports com.github.thomasdarimont.keycloak.mcp.config;

    exports com.github.thomasdarimont.keycloak.mcp.keycloak;

    exports com.github.thomasdarimont.keycloak.mcp.spi;

    // tool schemas and results are Vert.x JSON
    requires transitive io.vertx.core;

    // handlers work with the admin client's resources and representations
    requires transitive keycloak.admin.client;

    requires transitive keycloak.client.common.synced;

    requires transitive jakarta.ws.rs;

    // McpServerConfig is a SmallRye @ConfigMapping; the runtime is the server's
    requires static transitive io.smallrye.config;

    requires static transitive org.eclipse.microprofile.config;

}
