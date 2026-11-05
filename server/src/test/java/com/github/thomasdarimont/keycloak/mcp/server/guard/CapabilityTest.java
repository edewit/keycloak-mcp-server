package com.github.thomasdarimont.keycloak.mcp.server.guard;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.info.FeatureRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.keycloak.representations.info.SystemInfoRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Requirement;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;
import com.github.thomasdarimont.keycloak.mcp.server.keycloak.DefaultKeycloakAdmin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CapabilityTest {

    static ServerCapabilities caps(String version, String... features) {
        return new ServerCapabilities(version, Set.of(features), true);
    }

    @Test
    void versionsCompareNumerically() {
        assertTrue(ServerCapabilities.compareVersions("26.10.0", "26.8.1") > 0);
        assertTrue(ServerCapabilities.compareVersions("26.8", "26.8.0") == 0);
        assertTrue(ServerCapabilities.compareVersions("25.0.6", "26.8") < 0);
        assertTrue(caps("999.0.0-SNAPSHOT").atLeast("26.8"));
        assertTrue(caps("26.8.1").atLeast("26.8"));
        assertFalse(caps("26.7.0").atLeast("26.8"));
        assertFalse(ServerCapabilities.UNKNOWN.atLeast("1.0"));
        assertTrue(caps("26.8.1").atMost("26"));
        assertTrue(caps("26.8.3").atMost("26.8"));
        assertFalse(caps("26.9.0").atMost("26.8"));
        assertTrue(caps("26.8").atMost("26.8.0"));
        assertFalse(ServerCapabilities.UNKNOWN.atMost("99"));
    }

    @Test
    void featureNamesAreNormalized() {
        ServerCapabilities c = caps("26.8.1", "ORGANIZATION", "PASSKEYS");
        assertTrue(c.hasFeature("organization"));
        assertTrue(c.hasFeature("Organization"));
        assertTrue(c.hasFeature("PASSKEYS"));
        assertFalse(c.hasFeature("admin-fine-grained-authz-v2"));
        assertEquals(Set.of("organization", "passkeys"), c.features());
    }

    @Test
    void readsTheServerInfo() {
        ServerInfoRepresentation info = new ServerInfoRepresentation();
        SystemInfoRepresentation sys = new SystemInfoRepresentation();
        sys.setVersion("26.8.1");
        info.setSystemInfo(sys);
        FeatureRepresentation on = new FeatureRepresentation();
        on.setName("ORGANIZATION");
        on.setEnabled(true);
        FeatureRepresentation off = new FeatureRepresentation();
        off.setName("PASSKEYS");
        off.setEnabled(false);
        info.setFeatures(List.of(on, off));

        ServerCapabilities c = ServerCapabilities.of(info);
        assertEquals("26.8.1", c.version());
        assertTrue(c.featuresKnown());
        assertEquals(Set.of("organization"), c.features());
        assertEquals("26.9.0", c.withVersion("26.9.0").version());
        assertFalse(ServerCapabilities.of(new ServerInfoRepresentation()).featuresKnown());
    }

    @Test
    void requirementsPassWhenUnknownAndExplainWhenUnmet() {
        Requirement org = Requirement.feature("Organization");
        Requirement v = Requirement.minVersion("26.9");
        assertEquals("feature:organization", org.describe());
        assertEquals("version>=26.9", v.describe());

        assertTrue(org.unmet(ServerCapabilities.UNKNOWN).isEmpty());
        assertTrue(v.unmet(ServerCapabilities.UNKNOWN).isEmpty());
        assertTrue(org.unmet(caps("26.8.1", "organization")).isEmpty());
        assertTrue(v.unmet(caps("26.10.0")).isEmpty());

        String why = org.unmet(caps("26.8.1", "passkeys")).orElseThrow();
        assertTrue(why.contains("KC_FEATURE_ORGANIZATION=enabled"), why);
        assertTrue(why.contains("https://www.keycloak.org/server/features"), why);
        assertTrue(why.contains("26.8.1"), why);
        String old = v.unmet(caps("26.8.1")).orElseThrow();
        assertTrue(old.contains("26.9 or newer"), old);

        // plain wording for users: no configuration options, an admin can change it
        String plain = org.unmet(caps("26.8.1", "passkeys"), Explanations.USERS).orElseThrow();
        assertTrue(plain.contains("not available on this Keycloak server"), plain);
        assertTrue(plain.contains("administrator can enable it"), plain);
        assertFalse(plain.contains("KC_FEATURE"), plain);
        assertTrue(org.unmet(caps("26.8.1", "organization"), Explanations.USERS).isEmpty());
        assertTrue(v.unmet(caps("26.8.1"), Explanations.USERS).orElseThrow().contains("would have to upgrade"));
        assertTrue(Requirement.maxVersion("26")
            .unmet(caps("27.0.0"), Explanations.USERS)
            .orElseThrow()
            .contains("no longer available"));

        Requirement gone = Requirement.maxVersion("26.9");
        assertEquals("version<=26.9", gone.describe());
        assertTrue(gone.unmet(ServerCapabilities.UNKNOWN).isEmpty());
        assertTrue(gone.unmet(caps("26.9.3")).isEmpty(), "inclusive at the precision given");
        assertTrue(gone.unmet(caps("26.8.1")).isEmpty());
        assertTrue(gone.unmet(caps("26.10.0")).orElseThrow().contains("up to 26.9;"));
        assertTrue(Requirement.maxVersion("26").unmet(caps("26.8.1")).isEmpty());
        assertTrue(Requirement.maxVersion("26").unmet(caps("27.0.0")).isPresent());
    }

    @Test
    void discoveryCachesPerSystemAndKeepsUnknownShort() {
        AtomicInteger loads = new AtomicInteger();
        CapabilityDiscovery d = new CapabilityDiscovery(List.of("a", "b"), name -> {
            loads.incrementAndGet();
            return name.equals("a") ? caps("26.8.1", "organization") : ServerCapabilities.UNKNOWN;
        });
        assertEquals(ServerCapabilities.UNKNOWN, d.peek("a"));
        assertEquals("26.8.1", d.get("a").version());
        assertEquals("26.8.1", d.get("a").version());
        assertEquals(1, loads.get(), "cached");
        assertEquals("26.8.1", d.peek("a").version());
        assertFalse(d.get("b").versionKnown());
        assertEquals(ServerCapabilities.UNKNOWN, d.get("nope"));
        assertEquals(2, loads.get());
        d.invalidate();
        d.get("a");
        assertEquals(3, loads.get());
        assertEquals("26.8.1", CapabilityDiscovery.fixed(caps("26.8.1")).get().version());
    }

    @Test
    void configuredVersionStandsInWhenTheServerInfoIsNotReadable() {
        KeycloakSystem unreachable = new KeycloakSystem("default", "http://127.0.0.1:1", GrantType.CLIENT_CREDENTIALS,
                ClientAuth.NONE, "master", Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Set.of(), Optional.of("26.8.1"));
        DefaultKeycloakAdmin admin = new DefaultKeycloakAdmin(unreachable, null);
        try {
            ServerCapabilities c = CapabilityDiscovery.load(admin);
            assertEquals("26.8.1", c.version());
            assertFalse(c.featuresKnown());
            assertTrue(Requirement.feature("organization").unmet(c).isEmpty(), "features unknown: not gated");
            assertTrue(Requirement.minVersion("26.9").unmet(c).isPresent(), "version known: gated");
        }
        finally {
            admin.close();
        }
    }
}
