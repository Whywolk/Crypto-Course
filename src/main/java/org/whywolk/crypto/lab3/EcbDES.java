package org.whywolk.crypto.lab3;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class EcbDES {

    public static String encrypt(String message, String key) {
        String hexKey = DES.genKey(key);
        byte[] keyBytes = DES.hexKeyToBytes(hexKey);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = EcbDES.splitIntoBlocks(messageBytes);

        // encrypt every block
        StringBuilder encMessage = new StringBuilder();
        for (byte[] block: messageBlocks) {
            byte[] encBlock = DES.encryptBlock(block, keyBytes);

            // every block to hex
            for (byte b: encBlock) {
                encMessage.append(String.format("%02x", b));
            }
        }

        return encMessage.toString();
    }

    public static String decrypt(String encMessage, String key) {
        String hexKey = DES.genKey(key);
        byte[] keyBytes = DES.hexKeyToBytes(hexKey);
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = EcbDES.splitIntoBlocks(messageBytes);

        // decrypt every block
        StringBuilder decMessage = new StringBuilder();
        for (byte[] block: messageBlocks) {
            byte[] decBlock = DES.decryptBlock(block, keyBytes);
            decMessage.append(new String(EcbDES.reduceZeros(decBlock), StandardCharsets.UTF_8));
        }

        return decMessage.toString();
    }

    private static byte[][] splitIntoBlocks(byte[] bytes) {
        int size = bytes.length / 8;
        if (bytes.length % 8 != 0) {
            size += 1;
        }
        byte[][] blocks = new byte[size][8];
        for (int i = 0; i < bytes.length; i++) {
            blocks[i/8][i%8] = bytes[i];
        }
        return blocks;
    }

    private static byte[] reduceZeros(byte[] b) {
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
