package org.whywolk.crypto.lab2;

import org.junit.Assert;
import org.junit.Test;

public class XORCypherTest extends Assert {

    @Test
    public void testEncryption() {
        String message = "HELLOладноそれが";
        Integer key = 127;

        String encrypted = null;
        try {
            encrypted = XORCipher.encrypt(message, key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String decrypted = null;
        try {
            decrypted = XORCipher.decrypt(encrypted, key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        assertEquals(message, decrypted);
    }
}
