package org.whywolk.crypto.lab3;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class EcbDES {

    /**
     * @param message open message
     * @param key password
     * @return encrypted message in hex string
     */
    public static String encrypt(String message, String key) {
        byte[] keyBytes = DESUtils.genKey(key);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = DESUtils.splitIntoBlocks(messageBytes, 8);

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

    /**
     * @param encMessage encrypted message
     * @param key password
     * @return open message
     */
    public static String decrypt(String encMessage, String key) {
        byte[] keyBytes = DESUtils.genKey(key);
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = DESUtils.splitIntoBlocks(messageBytes, 8);

        // decrypt every block
        StringBuilder decMessage = new StringBuilder();
        for (byte[] block: messageBlocks) {
            byte[] decBlock = DES.decryptBlock(block, keyBytes);
            decMessage.append(new String(DESUtils.reduceZeros(decBlock), StandardCharsets.UTF_8));
        }

        return decMessage.toString();
    }
}
