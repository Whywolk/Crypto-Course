package org.whywolk.crypto.lab1;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PolybiusSquare {

    private static final int tableWidth = 5;
    private static final int tableHeight = 5;

    private static final List<String> englishLetters = Arrays.asList(
            "A", "B", "C", "D", "E",
            "F", "G", "H", "I/J", "K",
            "L", "M", "N", "O", "P",
            "Q", "R", "S", "T", "U",
            "V", "W", "X", "Y", "Z"
    );

    /**
     * Encrypt message using key
     *
     * @param message open message
     * @param key password, if empty then A-Z password
     * @return encrypted message
     * @throws Exception
     */
    public static String encrypt(String message, String key) throws Exception {
        StringBuilder encryptedMessage = new StringBuilder();

        if(isRightLetters(message) && isRightLetters(key)) {
            String[][] table = getTable(key);

            // Encrypt every letter
            for (Character letter: message.toCharArray()) {
                int[] ij = getLetterIdx(Character.toString(letter), table);
                int i = ij[0];

                // Original letter below in table at the same line
                int j = ij[1] + 1;
                if (j >= table[i].length) {
                    j = 0;
                }

                String resChar = table[i][j];
                // There is no difference between 'I' and 'J', so set enc char to 'I'
                if (resChar.equals("I/J")) resChar = "I";
                encryptedMessage.append(resChar);
            }
        }

        return encryptedMessage.toString();
    }

    /**
     * Decrypt message using key
     *
     * @param encMessage encrypted message
     * @param key password, if empty then A-Z password
     * @return decrypted message
     * @throws Exception
     */
    public static String decrypt(String encMessage, String key) throws Exception {
        StringBuilder decryptedMessage = new StringBuilder();

        if(isRightLetters(encMessage) && isRightLetters(key)) {
            String[][] table = getTable(key);

            // Decrypt every letter
            for (Character letter: encMessage.toCharArray()) {
                String curChar = Character.toString(letter);

                // There is no difference between 'I' and 'J'
                if (curChar.equals("I")) {
                    curChar = "I/J";
                }
                int[] ij = getLetterIdx(curChar, table);
                int i = ij[0];

                // Original letter above in table at the same line
                int j = ij[1] - 1;
                if (j == -1) {
                    j = table[i].length - 1;
                }
                decryptedMessage.append(table[i][j]);
            }
        }

        return decryptedMessage.toString();
    }

    // Fill table and return it
    protected static String[][] getTable(String key) throws Exception {
        if (key.length() > tableWidth*tableHeight) {
            throw new Exception("Key length should be lesser 26");
        }
        if (!keyHasUniqueLetters(key)) {
            throw new Exception("Key should contain unique letters");
        } else {
            String[][] table = new String[tableHeight][tableWidth];
            HashSet<String> keySet = new HashSet<>();

            int curCharPos = 0;
            int curLetterPos = 0;
            for (int i = 0; i < tableHeight; i++) {
                for (int j = 0; j < tableWidth; j++) {

                    // First fill table key letters
                    if (curCharPos < key.length()) {
                        String curChar = Character.toString(key.charAt(curCharPos));
                        if (curChar.equals("I") || curChar.equals("J")) {
                            curChar = "I/J";
                        }
                        keySet.add(curChar);
                        table[i][j] = curChar;
                        curCharPos++;
                    }
                    // Then fill with remaining letters
                    else {
                        String curLetter = englishLetters.get(curLetterPos);
                        while (keySet.contains(curLetter)) {
                            curLetterPos++;
                            curLetter = englishLetters.get(curLetterPos);
                        }
                        table[i][j] = curLetter;
                        curLetterPos++;
                    }
                }
            }
            return table;
        }
    }

    // Find and return position (x, y) of letter in table
    private static int[] getLetterIdx(String letter, String[][] table) throws Exception {
        for (int i = 0; i < table.length; i++) {
            for (int j = 0; j < table[i].length; j++) {
                if (table[i][j].contains(letter)) {
                    return new int[]{i, j};
                }
            }
        }
        throw new Exception("Unexpected letter '" + letter + "'");
    }

    private static boolean keyHasUniqueLetters(String key) {
        // Set will be contain only unique elements
        HashSet<Character> chars = new HashSet<>();
        for (Character letter: key.toCharArray()) {
            chars.add(letter);
        }
        return chars.size() == key.length();
    }

    // Checking some string (message on key for example) that it's contains only 'A-Z' chars
    private static boolean isRightLetters(String s) throws Exception {
        if (s.isEmpty()) return true;

        Pattern p = Pattern.compile("^[A-Z]+$");
        Matcher m = p.matcher(s);
        if (m.matches()) {
            return true;
        } else {
            throw new Exception("Sequence '" + s + "' should contain only letters A-Z");
        }
    }
}
