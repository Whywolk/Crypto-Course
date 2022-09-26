package org.whywolk.crypto.lab2;

import org.junit.Assert;
import org.junit.Test;

public class XORCypherTest extends Assert {

    @Test
    public void testEncryption() {
        String message = "Alex desu";
        String key = "スッパシクレっと";

        String encrypted = XORCipher.encrypt(message, key);
        String decrypted = XORCipher.decrypt(encrypted, key);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptionEmptyPassword() {
        String message = "Alex desu";
        String key = "";

        String encrypted = XORCipher.encrypt(message, key);
        String decrypted = XORCipher.decrypt(encrypted, key);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptionEmptyMessage() {
        String message = "";
        String key = "";

        String encrypted = XORCipher.encrypt(message, key);
        String decrypted = XORCipher.decrypt(encrypted, key);

        assertEquals(message, decrypted);
    }

    @Test
    public void testWrongPassword() {
        String message = "Alex desu";
        String key = "スッパシクレっと";
        String wrongKey = "some_pass";

        String encrypted = XORCipher.encrypt(message, key);
        String decrypted = XORCipher.decrypt(encrypted, wrongKey);

        assertNotEquals(message, decrypted);
    }
}
