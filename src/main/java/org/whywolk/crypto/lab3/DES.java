package org.whywolk.crypto.lab3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

public class DES {

    private static final int[] IP_TABLE = {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final int[] IP_TABLE_INV = {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
    };

    private static final int[] E_TABLE = {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
    };

    private static final int[] P_TABLE = {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
    };

    private static final int[][] S1 = {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };

    private static final int[][] S2 = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    };

    private static final int[][] S3 = {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    };

    private static final int[][] S4 = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    };

    private static final int[][] S5 = {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    };

    private static final int[][] S6 = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    };

    private static final int[][] S7 = {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    };

    private static final int[][] S8 = {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    };

    private static final int[][][] S = {S1, S2, S3, S4, S5, S6, S7, S8};

    private static final int[] C0_TABLE = {
            57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36
    };

    private static final int[] D0_TABLE = {
            63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
    };

    private static final int[] SHIFT_TABLE = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    private static final int[] KEY_TABLE = {
            14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4,
            26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    public static byte[] encryptBlock(byte[] message, byte[] key) {
        if (message.length != 8) throw new RuntimeException("Message length should be 64 bits");

        byte[] IP = DES.initialPermutation(message);
        byte[] left = Arrays.copyOfRange(IP, 0, IP.length/2);
        byte[] right = Arrays.copyOfRange(IP, IP.length/2, IP.length);
        byte[][] keys = DES.generateKeys(key);

        for (int stage = 0; stage <= 15; stage++) {
            byte[] resF = DES.f(right, keys[stage]);
            for (int i = 0; i < resF.length; i++) {
                resF[i] ^= left[i];
            }
            left = right;
            right = resF;
        }
        byte[] T = DES.concatArrays(right, left);
        byte[] enc = DES.finalPermutation(T);
        return enc;
    }

    public static byte[] decryptBlock(byte[] message, byte[] key) {
        if (message.length != 8) throw new RuntimeException("Message length should be 64 bits");

        byte[] IP = DES.initialPermutation(message);
        byte[] left = Arrays.copyOfRange(IP, 0, IP.length/2);
        byte[] right = Arrays.copyOfRange(IP, IP.length/2, IP.length);
        byte[][] keys = DES.generateKeys(key);

        for (int stage = 15; stage >= 0; stage--) {
            byte[] resF = DES.f(right, keys[stage]);
            for (int i = 0; i < resF.length; i++) {
                resF[i] ^= left[i];
            }
            left = right;
            right = resF;
        }

        byte[] T = DES.concatArrays(right, left);
        byte[] dec = DES.finalPermutation(T);
        return dec;
    }

    public static String genKey(String key) {
        StringBuilder hex = new StringBuilder();
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
        if (keyBytes.length > 8) throw new RuntimeException("Key length should be 8 chars");

        for (byte b: keyBytes) {
            b = (byte) (b << 1);
            if (b % 2 == 0) {
                b += 1;
            }
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    }

    public static byte[] hexKeyToBytes(String hex) {
        byte[] keyBytes = HexFormat.of().parseHex(hex);
        if (keyBytes.length != 8) throw new RuntimeException("Key length should be 8 chars");
        return keyBytes;
    }

    protected static byte[] initialPermutation(byte[] input) {
        byte[] inputBits = DES.toBits(input);
        byte[] outBits = new byte[inputBits.length];

        // bits permutation
        for (int i = 0; i < outBits.length; i++) {
            int idx = IP_TABLE[i] - 1;
            outBits[i] = inputBits[idx];
        }

        return DES.toBytes(outBits);
    }

    protected static byte[] finalPermutation(byte[] input) {
        byte[] inputBits = DES.toBits(input);
        byte[] outBits = new byte[inputBits.length];

        for (int i = 0; i < IP_TABLE_INV.length; i++) {
            int idx = IP_TABLE_INV[i] - 1;
            outBits[i] = inputBits[idx];
        }
        return DES.toBytes(outBits);
    }

    protected static byte[] f(byte[] vec, byte[] key) {
        if (vec.length != 4) throw new RuntimeException("Vector length should be 32 bits");
        if (key.length != 6) throw new RuntimeException("Key length should be 48 bits");

        // extend vector from 4 bytes to 6 bytes
        byte[] extendedVec = DES.extend(vec);

        // xor 6 byte extended vector with 6 byte key
        for (int i = 0; i < extendedVec.length; i++) {
            extendedVec[i] ^= key[i];
        }

        // 6 bits to 4 bits
        byte[] newB = DES.SBoxesTransmutation(extendedVec);

        byte[] newBbits = DES.toBits(newB);
        // permutation newB with P_TABLE
        byte[] outBits = new byte[P_TABLE.length];
        for (int i = 0; i < P_TABLE.length; i++) {
            int idx = P_TABLE[i] - 1;
            outBits[i] = newBbits[idx];
        }

        return DES.toBytes(outBits);
    }

    protected static byte[] SBoxesTransmutation(byte[] B) {
        byte[] Bbits = DES.toBits(B);

        // split vector B into eight 6 bits vectors
        byte[][] Bi = new byte[8][6];
        for (int i = 0; i < Bbits.length; i++) {
            Bi[i/6][i%6] = Bbits[i];
        }

        // transmutation 6 bits Bi to 4 bits newBi
        byte[] newBi = new byte[Bi.length];
        byte[] newB = new byte[P_TABLE.length];
        for (int i = 0; i < newBi.length; i++) {
            // first and last bits of B[i]
            int a = (Bi[i][0] << 1) + (Bi[i][Bi[i].length-1]);

            // center 4 bits of B[i]
            int b = 0;
            for (int j = 1; j < 5; j++) {
                b += Bi[i][j] << (4 - j);
            }

            newBi[i] = (byte) S[i][a][b];
        }

        // newBi bits array to newB bits array
        for (int i = 0; i < newBi.length; i++) {
            byte[] curBiBits = Arrays.copyOfRange(DES.toBits(newBi[i]), 4, 8);
            for (int j = 0; j < curBiBits.length; j++) {
                newB[i*4 + j] = curBiBits[j];
            }
        }
        return DES.toBytes(newB);
    }

    // Extend vec from 32 bits to 48 bits with E_TABLE
    protected static byte[] extend(byte[] vec) {
        byte[] vecBits = DES.toBits(vec);
        byte[] extendedVec = new byte[DES.E_TABLE.length];

        for (int i = 0; i < extendedVec.length; i++) {
            int idx = E_TABLE[i] - 1;
            extendedVec[i] = vecBits[idx];
        }

        return DES.toBytes(extendedVec);
    }

    protected static byte[][] generateKeys(byte[] key) {
        if (key.length != 8) throw new RuntimeException();
        byte[] keyBits = DES.toBits(key);
        byte[] C0 = new byte[C0_TABLE.length];
        byte[] D0 = new byte[D0_TABLE.length];

        for (int i = 0; i < C0_TABLE.length; i++) {
            int idx = C0_TABLE[i] - 1;
            C0[i] = keyBits[idx];
        }

        for (int i = 0; i < D0_TABLE.length; i++) {
            int idx = D0_TABLE[i] - 1;
            D0[i] = keyBits[idx];
        }
        byte[][] keysBits = new byte[16][KEY_TABLE.length];
        byte[][] keysBytes = new byte[16][KEY_TABLE.length/8];

        byte[] prevC = C0;
        byte[] prevD = D0;
        // generate 16 keys
        for (int i = 0; i < 16; i++) {
            DES.cyclicShiftLeft(prevC, SHIFT_TABLE[i]);
            DES.cyclicShiftLeft(prevD, SHIFT_TABLE[i]);
            byte[] curCD = DES.concatArrays(prevC, prevD);
            for (int j = 0; j < KEY_TABLE.length; j++) {
                int idx = KEY_TABLE[j] - 1;
                keysBits[i][j] = curCD[idx];
            }
            keysBytes[i] = DES.toBytes(keysBits[i]);
        }
        return keysBytes;
    }

    protected static byte[] toBits(byte b) {
        byte[] bits = new byte[8];
        for (int  i = 0; i < bits.length; i++) {
            bits[i] = (byte) ((b >>> (7 - i%8)) & 1);
        }
        return bits;
    }

    protected static byte[] toBits(byte[] bytes) {
        byte[] bits = new byte[bytes.length * 8];

        // split every byte into bits
        for (int i = 0; i < bits.length; i++) {
            byte curByte = bytes[i / 8];
            bits[i] = (byte) ((curByte >>> (7 - i%8)) & 1);
        }

        return bits;
    }

//    protected static byte toByte(byte[] bits) {
//        byte b = 0;
//        for (int i = 0; i < bits.length; i++) {
//            b[i / 8] += bits[i] << (i%8);
//        }
//    }

    protected static byte[] toBytes(byte[] bits) {
        byte[] bytes = new byte[bits.length / 8];

        // convert bits to bytes
        for (int i = 0; i < bits.length; i++) {
            bytes[i / 8] += bits[i] << (7 - i%8);
        }

        return bytes;
    }

    protected static byte[] cyclicShiftLeft(byte[] arr, int shift) {
        // copy left shifting els
        byte[] tmp = new byte[shift];
        for (int i = 0; i < shift; i++) {
            tmp[i] = arr[i];
        }
        // shift elements
        for (int i = 0; i < arr.length - shift; i++) {
            arr[i] = arr[i + shift];
        }
        // place tmp at the end of arr
        for (int i = 0; i < shift; i++) {
            arr[arr.length - shift + i] = tmp[i];
        }
        return arr;
    }

    protected static byte[] concatArrays(byte[] a, byte[] b) {
        byte[] newArr = new byte[a.length + b.length];
        for (int i = 0; i < a.length; i++) {
            newArr[i] += a[i];
        }
        for (int i = a.length; i < newArr.length; i++) {
            newArr[i] += b[i - b.length];
        }
        return newArr;
    }
}
