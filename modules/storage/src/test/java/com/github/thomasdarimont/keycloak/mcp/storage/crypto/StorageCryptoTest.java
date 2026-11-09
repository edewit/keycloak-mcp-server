package com.github.thomasdarimont.keycloak.mcp.storage.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StorageCryptoTest {

    @Test
    void encryptsWithAKeyAndPassesThroughWithout() {
        StorageCrypto off = new StorageCrypto((String) null);
        assertFalse(off.enabled());
        assertEquals("plain", off.protect("plain"));
        assertEquals("plain", off.reveal("plain"));
        assertNull(off.protect(null));

        StorageCrypto on = new StorageCrypto("a passphrase");
        assertTrue(on.enabled());
        String stored = on.protect("s3cr3t");
        assertTrue(StorageCrypto.isEncrypted(stored), stored);
        assertNotEquals(stored, on.protect("s3cr3t"), "a fresh nonce per value");
        assertEquals("s3cr3t", on.reveal(stored));
        assertEquals("legacy", on.reveal("legacy"), "rows written before encryption stay readable");

        assertThrows(IllegalStateException.class, () -> off.reveal(stored), "encrypted row without a key");
        assertThrows(IllegalStateException.class, () -> new StorageCrypto("other").reveal(stored), "wrong key");
    }

    @Test
    void acceptsARawBase64KeyOrDerivesOneFromAPassphrase() {
        byte[] raw = new byte[32];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) i;
        }
        String base64 = Base64.getEncoder().encodeToString(raw);
        StorageCrypto a = new StorageCrypto(base64);
        StorageCrypto b = new StorageCrypto(base64);
        assertEquals("x", b.reveal(a.protect("x")), "the same raw key on both sides");
        // 16 base64 bytes are not a key: treated as a passphrase, still deterministic
        String shortSecret = Base64.getEncoder().encodeToString(new byte[16]);
        assertEquals("y", new StorageCrypto(shortSecret).reveal(new StorageCrypto(shortSecret).protect("y")));
    }

    @Test
    void valuesNameTheirKeyAndPreviousKeysStillDecrypt() throws Exception {
        StorageCrypto old = new StorageCrypto("old-passphrase");
        StorageCrypto rotated = new StorageCrypto("new-passphrase", List.of("old-passphrase"));
        String oldKid = old.currentKeyId().orElseThrow();
        String newKid = rotated.currentKeyId().orElseThrow();
        assertEquals(8, newKid.length());
        assertNotEquals(oldKid, newKid);
        assertTrue(rotated.hasPreviousKeys());
        assertFalse(old.hasPreviousKeys());

        String underOld = old.protect("s3cr3t");
        assertTrue(underOld.startsWith("enc:v2:" + oldKid + ":"), underOld);
        assertEquals(oldKid, StorageCrypto.keyIdOf(underOld).orElseThrow());
        assertEquals("s3cr3t", rotated.reveal(underOld), "a previous key decrypts");
        assertTrue(rotated.needsRekey(underOld), "but the row is due for rewriting");

        String underNew = rotated.protect(rotated.reveal(underOld));
        assertEquals(newKid, StorageCrypto.keyIdOf(underNew).orElseThrow());
        assertFalse(rotated.needsRekey(underNew));
        assertEquals("s3cr3t", rotated.reveal(underNew));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> old.reveal(underNew),
                "the old instance does not know the new key");
        assertTrue(e.getMessage().contains(newKid) && e.getMessage().contains("previous-secret-keys"), e.getMessage());

        // the format before key ids: tried against every configured key
        byte[] nonce = new byte[12];
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, old.key(), new GCMParameterSpec(128, nonce));
        String legacy = "enc:v1:" + Base64.getEncoder().encodeToString(nonce) + ":"
                + Base64.getEncoder().encodeToString(cipher.doFinal("legacy".getBytes(StandardCharsets.UTF_8)));
        assertTrue(StorageCrypto.isEncrypted(legacy));
        assertEquals(StorageCrypto.LEGACY_KEY_ID, StorageCrypto.keyIdOf(legacy).orElseThrow());
        assertEquals("legacy", old.reveal(legacy));
        assertEquals("legacy", rotated.reveal(legacy), "through the previous key");
        assertTrue(rotated.needsRekey(legacy));
        assertThrows(IllegalStateException.class, () -> new StorageCrypto("new-passphrase").reveal(legacy));

        // plain values from before encryption are due as well, nothing is due without
        // encryption
        assertTrue(rotated.needsRekey("plain"));
        assertTrue(StorageCrypto.keyIdOf("plain").isEmpty());
        assertFalse(new StorageCrypto((String) null).needsRekey("plain"));
        assertFalse(rotated.needsRekey(null));
    }

    @Test
    void theDerivationCanBeReplaced() {
        class Fixed extends StorageCrypto {
            Fixed() {
                super("ignored, the key comes from elsewhere");
            }

            @Override
            protected SecretKey derive(String secret) {
                return new SecretKeySpec(new byte[32], "AES");
            }
        }
        String stored = new Fixed().protect("z");
        assertEquals("z", new Fixed().reveal(stored));
        assertThrows(IllegalStateException.class,
                () -> new StorageCrypto("ignored, the key comes from elsewhere").reveal(stored),
                "Argon2 derives a different key from the same string");
    }
}
