package com.github.thomasdarimont.keycloak.mcp.storage.crypto;

import java.util.Base64;

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
    void theDerivationCanBeReplaced() {
        class Fixed extends StorageCrypto {
            Fixed() {
                super("ignored, the key comes from elsewhere");
            }

            @Override
            protected javax.crypto.SecretKey derive(String secret) {
                return new javax.crypto.spec.SecretKeySpec(new byte[32], "AES");
            }
        }
        String stored = new Fixed().protect("z");
        assertEquals("z", new Fixed().reveal(stored));
        assertThrows(IllegalStateException.class,
                () -> new StorageCrypto("ignored, the key comes from elsewhere").reveal(stored),
                "Argon2 derives a different key from the same string");
    }
}
