package org.whywolk.crypto.lab2;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class XORCipher {

    /**
     * XOR message with key
     *
     * @param messageBytes message
     * @param keyBytes password
     * @return xor'ed message
     */
    public static byte[] clusterXor(byte[] messageBytes, byte[] keyBytes) {
        byte[] newMessageBytes = messageBytes.clone();

        // divide messageBytes into clusters with keyBytes length
        for (int cluster = 0; cluster <= (newMessageBytes.length / (keyBytes.length + 1)); cluster++) {
            // xor every byte of cluster with the same key byte
            for (int i = 0; i < keyBytes.length; i++) {
                int idx = cluster*keyBytes.length + i;

                // case, when keyBytes length more than cluster length
                if (idx < newMessageBytes.length) {
                    newMessageBytes[idx] ^= keyBytes[i];
                } else break;
            }
        }
        return newMessageBytes;
    }

    /**
     * XOR message with key
     *
     * @param messageBytes message
     * @param keyBytes password
     * @return xor'ed message
     */
    public static byte[] xor(byte[] messageBytes, byte[] keyBytes) {
        byte[] newMessageBytes = messageBytes.clone();
        // every byte of message
        for (int i = 0; i < newMessageBytes.length; i++) {
            // xor with each byte of key
            for (byte keyByte : keyBytes) {
                newMessageBytes[i] ^= keyByte;
            }
        }
        return newMessageBytes;
    }

    /**
     * Encrypt message using key
     *
     * @param message open message
     * @param key password
     * @return encrypted message
     */
    public static String encrypt(String message, Integer key) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = ByteBuffer.allocate(4).putInt(key).array();
        StringBuilder hex = new StringBuilder();

        for (byte b: clusterXor(messageBytes, keyBytes)) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    }

    /**
     * Encrypt message using key
     *
     * @param message open message
     * @param key password
     * @return encrypted message
     */
    public static String encrypt(String message, String key) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder();

        for (byte b: xor(messageBytes, keyBytes)) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    }

    /**
     * Decrypt message using key
     *
     * @param encMessage encrypted message
     * @param key password
     * @return decrypted message
     */
    public static String decrypt(String encMessage, Integer key) {
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);
        byte[] keyBytes = ByteBuffer.allocate(4).putInt(key).array();

        byte[] decryptedMessage = clusterXor(messageBytes, keyBytes);

        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt message using key
     *
     * @param encMessage encrypted message
     * @param key password
     * @return decrypted message
     */
    public static String decrypt(String encMessage, String key) {
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        byte[] decryptedMessage = xor(messageBytes, keyBytes);

        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }
}
