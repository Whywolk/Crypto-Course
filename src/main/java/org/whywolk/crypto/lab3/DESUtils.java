package org.whywolk.crypto.lab3;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class DESUtils {

    public static byte[] genKey(String key) {

        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
        if (keyBytes.length > 8) throw new RuntimeException("Key length should be 8 chars");

        for (byte b: keyBytes) {
            b = (byte) (b << 1);
            if (b % 2 == 0) {
                b += 1;
            }
        }
        return keyBytes;
    }

    public static String bytesKeyToHex(byte[] key) {
        StringBuilder hex = new StringBuilder();
        for (byte b: key) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static byte[] hexKeyToBytes(String hex) {
        byte[] keyBytes = HexFormat.of().parseHex(hex);
        if (keyBytes.length != 8) throw new RuntimeException("Key length should be 8 chars");
        return keyBytes;
    }

    public static byte[][] splitIntoBlocks(byte[] bytes, int blockSize) {
        int size = bytes.length / blockSize;
        if (bytes.length % blockSize != 0) {
            size += 1;
        }
        byte[][] blocks = new byte[size][blockSize];
        for (int i = 0; i < bytes.length; i++) {
            blocks[i / blockSize][i % blockSize] = bytes[i];
        }
        return blocks;
    }

    public static byte[] reduceZeros(byte[] b) {
        int size = b.length;
        for (int i = 0; i < b.length; i++) {
            if (b[i] == 0) {
                size = i;
                break;
            }
        }
        byte[] tmp = new byte[size];
        System.arraycopy(b, 0, tmp, 0, size);
        return tmp;
    }
}
