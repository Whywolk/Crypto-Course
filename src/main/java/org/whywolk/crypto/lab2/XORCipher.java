package org.whywolk.crypto.lab2;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class XORCipher {

    /**
     * Encrypt message using key
     *
     * @param message open message
     * @param key password
     * @return encrypted message
     * @throws Exception
     */
    public static String encrypt(String message, Integer key) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder();

        for (int i = 0; i < messageBytes.length; i++) {
            messageBytes[i] ^= key.byteValue();
            hex.append(String.format("%02x", messageBytes[i]));
        }
        return hex.toString();
    }

    /**
     * Encrypt message using key
     *
     * @param message open message
     * @param key password
     * @return encrypted message
     * @throws Exception
     */
    public static String encrypt(String message, String key) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder();

        for (int cluster = 0; cluster < messageBytes.length / keyBytes.length + 1; cluster++) {
            for (int i = 0; i < keyBytes.length; i++) {
                int idx = cluster*keyBytes.length + i;
                if (idx < messageBytes.length) {
                    messageBytes[idx] ^= keyBytes[i];
                    hex.append(String.format("%02x", messageBytes[idx]));
                } else break;
            }
        }
        return hex.toString();
    }

    /**
     * Decrypt message using key
     *
     * @param encMessage encrypted message
     * @param key password
     * @return decrypted message
     * @throws Exception
     */
    public static String decrypt(String encMessage, Integer key) throws Exception {
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);
        for (int i = 0; i < messageBytes.length; i++) {
            messageBytes[i] ^= key.byteValue();
        }
        return new String(messageBytes, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt message using key
     *
     * @param encMessage encrypted message
     * @param key password
     * @return decrypted message
     * @throws Exception
     */
    public static String decrypt(String encMessage, String key) throws Exception {
        byte[] messageBytes = HexFormat.of().parseHex(encMessage);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        for (int cluster = 0; cluster < messageBytes.length / keyBytes.length + 1; cluster++) {
            for (int i = 0; i < keyBytes.length; i++) {
                int idx = cluster*keyBytes.length + i;
                if (idx < messageBytes.length) {
                    messageBytes[idx] ^= keyBytes[i];
                } else break;
            }
        }
        return new String(messageBytes, StandardCharsets.UTF_8);
    }
}
