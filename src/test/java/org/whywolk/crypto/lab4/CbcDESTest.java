package org.whywolk.crypto.lab4;

import org.junit.Assert;
import org.junit.Test;

public class CbcDESTest extends Assert {

    @Test
    public void testEncryptionDecryptionRightKey() {
        String message = "Hello world!";
        String key = "Somekey1";
        String IV = "somevect";

        String enc = CbcDES.encrypt(message, key, IV);
        String dec = CbcDES.decrypt(enc, key, IV);

        assertEquals(message, dec);
    }

    @Test
    public void testEncryptionDecryptionWrongKey() {
        String message = "Hello world!";
        String key = "Somekey1";
        String wrongKey = "Somekey2";
        String IV = "somevect";
        String wrongIV = "otherVec";

        String enc = CbcDES.encrypt(message, key, IV);
        String dec = CbcDES.decrypt(enc, wrongKey, wrongIV);

        assertNotEquals(message, dec);
    }
}
