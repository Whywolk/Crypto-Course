package org.whywolk.crypto.lab3;

import org.junit.Assert;
import org.junit.Test;

public class EcbDESTest extends Assert {

    @Test
    public void testEncryptionDecryptionRightKey() {
        String message = "Hello world!";
        String key = "Somekey1";

        String enc = EcbDES.encrypt(message, key);
        String dec = EcbDES.decrypt(enc, key);

        assertEquals(message, dec);
    }

    @Test
    public void testEncryptionDecryptionWrongKey() {
        String message = "Hello world!";
        String key = "Somekey1";
        String wrongKey = "Somekey2";

        String enc = EcbDES.encrypt(message, key);
        String dec = EcbDES.decrypt(enc, wrongKey);

        assertNotEquals(message, dec);
    }
}
