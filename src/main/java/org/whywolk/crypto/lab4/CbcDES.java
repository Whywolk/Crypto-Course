package org.whywolk.crypto.lab4;

import org.whywolk.crypto.lab3.DES;
import org.whywolk.crypto.lab3.DESUtils;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class CbcDES {

    /**
     * @param message open message
     * @param key password
     * @param initVec initialization vector
     * @return encrypted message in hex string
     */
    public static String encrypt(String message, String key, String initVec) {
        byte[] keyBytes = DESUtils.genKey(key);
        byte[] IV = initVec.getBytes(StandardCharsets.US_ASCII);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        if (IV.length != 8) throw new RuntimeException("Initialization vector size should be 8 bytes");

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = DESUtils.splitIntoBlocks(messageBytes, 8);

        // encrypt every block
        StringBuilder encMessage = new StringBuilder();
        for (byte[] block: messageBlocks) {

            // xor block with init vec
            for (int i = 0; i < block.length; i++) {
                block[i] ^= IV[i];
            }

            byte[] encBlock = DES.encryptBlock(block, keyBytes);

            // update init vec for next iteration
            IV = encBlock.clone();

            // every block to hex
            for (byte b: encBlock) {
                encMessage.append(String.format("%02x", b));
            }
        }

        return encMessage.toString();
    }

    /**
     * @param encMessage encrypted message in hex string
     * @param key password
     * @param initVec initialization vector
     * @return open message
     */
    public static String decrypt(String encMessage, String key, String initVec) {
        byte[] keyBytes = DESUtils.genKey(key);
        byte[] IV = initVec.getBytes(StandardCharsets.US_ASCII);
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);

        if (IV.length != 8) throw new RuntimeException("Initialization vector size should be 8 bytes");

        // split messageBytes to 8 byte blocks
        byte[][] messageBlocks = DESUtils.splitIntoBlocks(messageBytes, 8);

        // decrypt every block
        StringBuilder decMessage = new StringBuilder();
        for (byte[] block: messageBlocks) {
            byte[] decBlock = DES.decryptBlock(block, keyBytes);

            // xor block with init vec
            for (int i = 0; i < decBlock.length; i++) {
                decBlock[i] ^= IV[i];
            }
            // update init vec for next iteration
            IV = block.clone();

            decMessage.append(new String(DESUtils.reduceZeros(decBlock), StandardCharsets.UTF_8));
        }

        return decMessage.toString();
    }
}
