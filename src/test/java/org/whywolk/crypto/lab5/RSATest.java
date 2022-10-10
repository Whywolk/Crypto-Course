package org.whywolk.crypto.lab5;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class RSATest extends Assert {

    @Test
    public void testCorrectKey() {
        BigInteger[] keys = RSA.generateKeys(16);
        BigInteger e = keys[0];
        BigInteger d = keys[2];
        BigInteger n = keys[1];

        BigInteger message = new BigInteger("Hello".getBytes(StandardCharsets.UTF_8));
        BigInteger encMessage = RSA.encrypt(message, e, n);
        BigInteger decMessage = RSA.decrypt(encMessage, d, n);
        if (! decMessage.equals(message)) {
            System.out.println();
        }

        assertEquals(message, decMessage);
    }

    @Test
    public void testWrongKey() {
        BigInteger[] keys = RSA.generateKeys(128);
        BigInteger e = keys[0];
        BigInteger n = keys[1];
        BigInteger d = RSA.generateKeys(128)[2];

        BigInteger message = new BigInteger("Hello".getBytes(StandardCharsets.UTF_8));
        BigInteger encMessage = RSA.encrypt(message, e, n);
        BigInteger decMessage = RSA.decrypt(encMessage, d, n);

        assertNotEquals(message, decMessage);
    }
}
