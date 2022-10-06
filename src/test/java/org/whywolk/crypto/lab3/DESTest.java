package org.whywolk.crypto.lab3;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class DESTest extends Assert {

    @Test
    public void testCyclicShift() {
        byte[] arr = new byte[] {1, 0, 1, 1, 0, 0, 1, 0};
        byte[] expected = new byte[] {1, 1, 0, 0, 1, 0, 1, 0};
        assertArrayEquals(expected, DES.cyclicShiftLeft(arr, 2));
    }

    @Test
    public void testConcatArrays() {
        byte[] a = new byte[] {1, 0, 1, 1, 0, 0, 1, 0};
        byte[] b = new byte[] {1, 1, 1, 1, 1, 1, 1, 1};
        byte[] ab = new byte[] {1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1};
        assertArrayEquals(ab, DES.concatArrays(a, b));
    }

    @Test
    public void testGenerateKeys() {
        byte[] keyBytes = new byte[] {
                (byte) 0b00010011, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11110001
        };
        byte[] key16 = new byte[] {
                (byte) 0b11001011, (byte) 0b00111101, (byte) 0b10001011,
                (byte) 0b00001110, (byte) 0b00010111, (byte) 0b11110101
        };
        byte[][] keys = DES.generateKeys(keyBytes);
        assertArrayEquals(key16, keys[15]);
    }

    @Test
    public void testInitialPermutation() {
        byte[] block = new byte[] {
                (byte) 0b00000001, (byte) 0b00100011, (byte) 0b01000101, (byte) 0b01100111,
                (byte) 0b10001001, (byte) 0b10101011, (byte) 0b11001101, (byte) 0b11101111
        };
        byte[] expected = new byte[] {
                (byte) 0b11001100, (byte) 0b00000000, (byte) 0b11001100, (byte) 0b11111111,
                (byte) 0b11110000, (byte) 0b10101010, (byte) 0b11110000, (byte) 0b10101010
        };
        byte[] IP = DES.initialPermutation(block);

        assertArrayEquals(expected, IP);
    }

    @Test
    public void testFinalPermutation() {
        byte[] vec = new byte[] {
                (byte) 0b00001010, (byte) 0b01001100, (byte) 0b11011001, (byte) 0b10010101,
                (byte) 0b01000011, (byte) 0b01000010, (byte) 0b00110010, (byte) 0b00110100
        };
        byte[] expected = new byte[] {
                (byte) 0b10000101, (byte) 0b11101000, (byte) 0b00010011, (byte) 0b01010100,
                (byte) 0b00001111, (byte) 0b00001010, (byte) 0b10110100, (byte) 0b00000101
        };
        byte[] IPinv = DES.finalPermutation(vec);

        assertArrayEquals(expected, IPinv);
    }

    @Test
    public void testExtendVec() {
        byte[] vec = new byte[] {
                (byte) 0b11110000, (byte) 0b10101010, (byte) 0b11110000, (byte) 0b10101010
        };
        byte[] expected = new byte[] {
                (byte) 0b01111010, (byte) 0b00010101, (byte) 0b01010101,
                (byte) 0b01111010, (byte) 0b00010101, (byte) 0b01010101
        };

        assertArrayEquals(expected, DES.extend(vec));
    }

    @Test
    public void testSBoxesTransmutation() {
        byte[] vec = new byte[] {
                (byte) 0b01100001, (byte) 0b00010111, (byte) 0b10111010,
                (byte) 0b10000110, (byte) 0b01100101, (byte) 0b00100111
        };
        byte[] expected = new byte[] {
                (byte) 0b01011100, (byte) 0b10000010, (byte) 0b10110101, (byte) 0b10010111
        };
        byte[] newB = DES.SBoxesTransmutation(vec);

        assertArrayEquals(expected, newB);
    }

    @Test
    public void testFfunction() {
        byte[] keyBytes = new byte[] {
                (byte) 0b00010011, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11110001
        };
        byte[] vec = new byte[] {
                (byte) 0b11110000, (byte) 0b10101010, (byte) 0b11110000, (byte) 0b10101010
        };
        byte[] expected = new byte[] {
                (byte) 0b00100011, (byte) 0b01001010, (byte) 0b10101001, (byte) 0b10111011
        };
        byte[] key1 = DES.generateKeys(keyBytes)[0];
        byte[] f = DES.f(vec, key1);

        assertArrayEquals(expected, f);
    }

    @Test
    public void testEncryption() {
        byte[] key = new byte[] {
                (byte) 0b00010011, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11110001
        };
        byte[] message = new byte[] {
                (byte) 0b00000001, (byte) 0b00100011, (byte) 0b01000101, (byte) 0b01100111,
                (byte) 0b10001001, (byte) 0b10101011, (byte) 0b11001101, (byte) 0b11101111
        };
        byte[] expected = new byte[] {
                (byte) 0b10000101, (byte) 0b11101000, (byte) 0b00010011, (byte) 0b01010100,
                (byte) 0b00001111, (byte) 0b00001010, (byte) 0b10110100, (byte) 0b00000101
        };
        byte[] encMsg = DES.encryptBlock(message, key);
        assertArrayEquals(expected, encMsg);
    }

    @Test
    public void testEncryptionDecryptionRightKey() {
        byte[] key = new byte[] {
                (byte) 0b00010011, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11110001
        };
        byte[] message = new byte[] {
                (byte) 0b00000001, (byte) 0b00100011, (byte) 0b01000101, (byte) 0b01100111,
                (byte) 0b10001001, (byte) 0b10101011, (byte) 0b11001101, (byte) 0b11101111
        };
        byte[] encMsg = DES.encryptBlock(message, key);
        byte[] decMsg = DES.decryptBlock(encMsg, key);

        assertArrayEquals(message, decMsg);
    }

    @Test
    public void testEncryptionDecryptionWrongKey() {
        byte[] key = new byte[] {
                (byte) 0b00010011, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11110001
        };
        byte[] wrongKey = new byte[] {
                (byte) 0b00000000, (byte) 0b00110100, (byte) 0b01010111, (byte) 0b01111001,
                (byte) 0b10011011, (byte) 0b10111100, (byte) 0b11011111, (byte) 0b11111111
        };
        byte[] message = new byte[] {
                (byte) 0b00000001, (byte) 0b00100011, (byte) 0b01000101, (byte) 0b01100111,
                (byte) 0b10001001, (byte) 0b10101011, (byte) 0b11001101, (byte) 0b11101111
        };
        byte[] encMsg = DES.encryptBlock(message, key);
        byte[] decMsg = DES.decryptBlock(encMsg, wrongKey);

        assertFalse(Arrays.equals(message, decMsg));
    }
}