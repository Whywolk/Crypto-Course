package org.whywolk.crypto.lab1;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

public class PolybiusSquareTest extends Assert {

    @Test
    public void testGetTable() {
        String key = "KEY";

        String[][] expectedTable = {
                {"K", "E", "Y", "A", "B"},
                {"C", "D", "F", "G", "H"},
                {"I/J", "L", "M", "N", "O"},
                {"P", "Q", "R", "S", "T"},
                {"U", "V", "W", "X", "Z"}};

        String[][] table = null;
        try {
            table = PolybiusSquare.getTable(key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        assertTrue(Arrays.deepEquals(expectedTable, table));
    }

    @Test
    public void testAll() {
        String message = "HELLO";
        String key = "PASWORD";

        String encrypted = null;
        try {
            encrypted = PolybiusSquare.encrypt(message, key);
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        String decrypted = null;
        try {
            decrypted = PolybiusSquare.decrypt(encrypted, key);
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryption() {
        String message = "HELLO";
        String key = "PASWORD";
        String expected = "IRMMP";

        String encrypted = null;
        try {
            encrypted = PolybiusSquare.encrypt(message, key);
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        assertEquals(expected, encrypted);
    }

    @Test(expected = Exception.class)
    public void testPasswordNotUnique() throws Exception {
        String message = "HELLO";
        String key = "PASSWORD";
        String encrypted = PolybiusSquare.encrypt(message, key);
    }

    @Test(expected = Exception.class)
    public void testPasswordLong() throws Exception {
        String message = "HELLO";
        String key = "QWERTYUIOPASDFGHJKLZXCVBNM";
        String encrypted = PolybiusSquare.encrypt(message, key);
    }

    @Test(expected = Exception.class)
    public void testWrongLetters() throws Exception {
        String message = "HELLO";
        String key = "Some Text";
        String encrypted = PolybiusSquare.encrypt(message, key);
    }
}
