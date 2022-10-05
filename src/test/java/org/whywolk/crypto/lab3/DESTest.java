package org.whywolk.crypto.lab3;

import org.junit.Assert;
import org.junit.Test;


public class DESTest extends Assert {

    @Test
    public void testInitialPermutation() {
        byte[] block = new byte[] {
                (byte) 0b01010101, (byte) 0b01010101, (byte) 0b01010101, (byte) 0b01010101,
                (byte) 0b01010101, (byte) 0b01010101, (byte) 0b01010101, (byte) 0b01010101
        };
        byte[] expected = new byte[] {
                (byte) 0b11111111, (byte) 0b11111111, (byte) 0b11111111, (byte) 0b11111111,
                (byte) 0b00000000, (byte) 0b00000000, (byte) 0b00000000, (byte) 0b00000000
        };

        byte[] IP = DES.initialPermutation(block);

        assertArrayEquals(expected, IP);
    }

    @Test
    public void testExtension() {

    }
}