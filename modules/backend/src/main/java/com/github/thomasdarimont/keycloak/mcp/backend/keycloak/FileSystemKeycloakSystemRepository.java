package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;
import com.google.auto.service.AutoService;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The built-in file {@link KeycloakSystemRepository}: systems from a JSON file
 * ({@code kc-mcp.systems-file}), re-read whenever the file changes, so a tenant registry
 * can be a mounted file that another process maintains. Active only with
 * {@code kc-mcp.dynamic-systems=true} and a configured file.
 *
 * <pre>
 * {"systems": [{"name": "tenant-a", "url": "https://sso-a.example.com", "authRealm": "tenant-a",
 *               "clientId": "keycloak-mcp-server", "clientAuth": "private_key_jwt",
 *               "defaultRealm": "tenant-a", "allowedRealms": ["tenant-a"]}]}
 * </pre>
 *
 * Fields: {@code name}, {@code url} (required); {@code grantType}
 * ({@code client_credentials}, default, or {@code password}); {@code clientAuth}
 * ({@code private_key_jwt}, default, {@code client_secret} or {@code none});
 * {@code authRealm} (default {@code master}); {@code clientId} (default
 * {@code keycloak-mcp-server}); {@code clientSecret}, {@code username}, {@code password},
 * {@code defaultRealm}, {@code trustedIssuers}, {@code allowedRealms}, {@code version},
 * {@code issuer} (the realm's public issuer URL when {@code url} is an internal address),
 * {@code displayName} (optional), {@code access} (the access checks that govern the
 * system's tool calls, see {@code AccessSettings}), {@code realms} (settings of single
 * realms, {@code {"<realm>": {"displayName": "...", "access": {...}}}}).
 */
@AutoService(KeycloakSystemRepository.class)
public class FileSystemKeycloakSystemRepository implements KeycloakSystemRepository {

    private static final Logger LOG = Logger.getLogger(FileSystemKeycloakSystemRepository.class);

    public static final String PROPERTY = "kc-mcp.systems-file";
    public static final String DEFAULT_CLIENT_ID = "keycloak-mcp-server";

    private final Path file;
    private final ReentrantLock reload = new ReentrantLock();
    private volatile FileTime loadedAt;
    private volatile Map<String, KeycloakSystem> systems = Map.of();

    /**
     * ServiceLoader constructor: the file from {@code kc-mcp.systems-file}, none when
     * unset.
     */
    public FileSystemKeycloakSystemRepository() {
        this(ConfigProvider.getConfig()
            .getOptionalValue(PROPERTY, String.class)
            .filter(v -> !v.isBlank())
            .map(Extensions::resolve)
            .orElse(null));
    }

    public FileSystemKeycloakSystemRepository(Path file) {
        this.file = file;
        if (file != null) {
            LOG.infof("Keycloak systems file: %s", file);
        }
    }

    @Override
    public String id() {
        return "file-system";
    }

    @Override
    public String description() {
        return file == null ? "no " + PROPERTY + " configured" : "systems from " + file;
    }

    @Override
    public List<String> names() {
        return List.copyOf(current().keySet());
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        return Optional.ofNullable(current().get(name));
    }

    private Map<String, KeycloakSystem> current() {
        if (file == null || !Files.isRegularFile(file)) {
            return Map.of();
        }
        try {
            FileTime modified = Files.getLastModifiedTime(file);
            if (!modified.equals(loadedAt)) {
                // a lock, not synchronized: the file is read while holding it, which
                // would pin a virtual
                // thread's carrier on JDK 21
                reload.lock();
                try {
                    if (!modified.equals(loadedAt)) {
                        systems = parse(new JsonObject(Files.readString(file)));
                        loadedAt = modified;
                        LOG.infof("Keycloak systems file %s: %s", file, systems.keySet());
                    }
                }
                finally {
                    reload.unlock();
                }
            }
        }
        catch (IOException | RuntimeException e) {
            LOG.warnf("Cannot read the Keycloak systems file %s: %s", file, e.toString());
        }
        return systems;
    }

    /** The systems of a document; see the class comment for the fields. */
    public static Map<String, KeycloakSystem> parse(JsonObject doc) {
        Map<String, KeycloakSystem> out = new LinkedHashMap<>();
        JsonArray list = doc.getJsonArray("systems", new JsonArray());
        for (int i = 0; i < list.size(); i++) {
            KeycloakSystem system = parseSystem(list.getJsonObject(i), null);
            out.put(system.name(), system);
        }
        return out;
    }

    /**
     * One system from its JSON object (the fields of the class comment, plus
     * {@code displayName} and {@code description}); the admin API uses the same shape.
     *
     * @param name the system name when it is not in the object ({@code name} or
     * {@code alias}), e.g. from a path
     */
    public static KeycloakSystem parseSystem(JsonObject s, String name) {
        String alias = name != null && !name.isBlank() ? name.trim()
                : optional(s, "name").or(() -> optional(s, "alias"))
                    .orElseThrow(() -> new IllegalArgumentException("A system lacks 'name': " + s.encode()));
        String url = require(s, "url");
        GrantType grant = s.getString("grantType") == null ? GrantType.CLIENT_CREDENTIALS
                : GrantType.parse(s.getString("grantType"));
        ClientAuth auth = s.getString("clientAuth") == null ? ClientAuth.PRIVATE_KEY_JWT
                : ClientAuth.parse(s.getString("clientAuth"));
        JsonArray realms = s.getJsonArray("allowedRealms", new JsonArray());
        KeycloakSystem.Builder system = KeycloakSystem.builder(alias, url)
            .grantType(grant)
            .clientAuth(auth)
            .authRealm(s.getString("authRealm", "master"))
            .clientId(s.getString("clientId", DEFAULT_CLIENT_ID))
            .clientSecret(s.getString("clientSecret"))
            .username(s.getString("username"))
            .password(s.getString("password"))
            .defaultRealm(s.getString("defaultRealm"))
            .version(s.getString("version"))
            .issuer(s.getString("issuer"))
            .displayName(s.getString("displayName"))
            .description(s.getString("description"));
        for (int j = 0; j < realms.size(); j++) {
            system.allowedRealm(realms.getString(j));
        }
        JsonArray issuers = s.getJsonArray("trustedIssuers", new JsonArray());
        for (int j = 0; j < issuers.size(); j++) {
            system.trustedIssuer(issuers.getString(j));
        }
        Object access = s.getValue("access");
        if (access != null && !(access instanceof JsonObject)) {
            throw new IllegalArgumentException("'access' of system '" + alias + "' must map check ids to settings");
        }
        system.access(AccessSettings.fromJson((JsonObject) access, "access."));
        Object tools = s.getValue("tools");
        if (tools != null && !(tools instanceof JsonObject)) {
            throw new IllegalArgumentException("'tools' of system '" + alias + "' must be an object");
        }
        system.tools(ToolSettings.fromJson((JsonObject) tools, "tools."));
        Object preset = s.getValue("preset");
        if (preset != null && !(preset instanceof String)) {
            throw new IllegalArgumentException("'preset' of system '" + alias + "' must be the name of a preset");
        }
        system.preset((String) preset);
        Object presets = s.getValue("presets");
        if (presets != null && !(presets instanceof JsonObject)) {
            throw new IllegalArgumentException("'presets' of system '" + alias + "' must map names to presets");
        }
        if (presets instanceof JsonObject byName) {
            List<Preset> own = new ArrayList<>();
            for (String presetName : byName.fieldNames()) {
                Object p = byName.getValue(presetName);
                if (!(p instanceof JsonObject json)) {
                    throw new IllegalArgumentException(
                            "presets." + presetName + " of system '" + alias + "' must be an object");
                }
                own.add(Preset.fromJson(presetName, json, "presets." + presetName + "."));
            }
            system.presets(own);
        }
        Object realmSettings = s.getValue("realms");
        if (realmSettings != null && !(realmSettings instanceof JsonObject)) {
            throw new IllegalArgumentException("'realms' of system '" + alias + "' must map realm names to settings");
        }
        if (realmSettings instanceof JsonObject byName) {
            for (String realm : byName.fieldNames()) {
                Object settings = byName.getValue(realm);
                if (settings != null && !(settings instanceof JsonObject)) {
                    throw new IllegalArgumentException(
                            "realms." + realm + " of system '" + alias + "' must be an object");
                }
                system.realm(RealmSettings.fromJson(realm, (JsonObject) settings));
            }
        }
        return system.build();
    }

    private static String require(JsonObject s, String field) {
        String v = s.getString(field);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("A system lacks '" + field + "': " + s.encode());
        }
        return v.trim();
    }

    private static Optional<String> optional(JsonObject s, String field) {
        String v = s.getString(field);
        return v == null || v.isBlank() ? Optional.empty() : Optional.of(v.trim());
    }
}
