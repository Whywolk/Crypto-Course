package org.whywolk.crypto.lab1;

import java.util.HashSet;
import java.util.Locale;

public class PolybiusSquare {

    private static final String[] englishLetters = {
            "A", "B", "C", "D", "E", "F", "G", "H", "I/J", "K",
            "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

    private static final String[][] englishSquare = {
            {"A", "B", "C", "D", "E"},
            {"F", "G", "H", "I/J", "K"},
            {"L", "M", "N", "O", "P"},
            {"Q", "R", "S", "T", "U"},
            {"V", "W", "X", "Y", "Z"}
    };

    public static String encrypt(String message, String key) throws Exception {
        message = message.toUpperCase(Locale.ROOT);
        key = key.toUpperCase(Locale.ROOT);
        StringBuilder encryptedMessage = new StringBuilder();

        String[][] table = getTable(key);
        for (Character letter: message.toCharArray()) {
            int[] ij = getLetterIdx(Character.toString(letter), table);
            int i = ij[0];
            int j = ij[1] + 1;

            if (j >= table[i].length) {
                j = 0;
            }
            encryptedMessage.append(table[i][j]);
        }

        return encryptedMessage.toString();
    }

    public static String decrypt(String message, String key) throws Exception {
        key = key.toUpperCase(Locale.ROOT);
        StringBuilder decryptedMessage = new StringBuilder();

        String[][] table = getTable(key);

        char[] arr = message.toCharArray();
        int curPos = 0;
        while (curPos < arr.length) {
            String curChar = Character.toString(arr[curPos]);
            if (curChar.equals("I")) {
                curChar = "I/J";
                curPos += 2;
            }
            int[] ij = getLetterIdx(curChar, table);
            int i = ij[0];
            int j = ij[1] - 1;

            if (j == -1) {
                j = table[i].length - 1;
            }
            decryptedMessage.append(table[i][j]);
            curPos++;
        }

        return decryptedMessage.toString();
    }

    protected static String[][] getTable(String key) throws Exception {
        if (key.length() > 25) {
            throw new Exception("Key length should be lesser 26");
        }
        if (key.length() == 0) {
            throw new Exception("Key should not be empty");
        }
        if (keyHasUniqueLetters(key)) {
            String[][] table = new String[5][5];
            HashSet<String> key_set = new HashSet<>();

            int curCharPos = 0;
            int curLetterPos = 0;
            int i;
            int j;
            for (i = 0; i < englishSquare.length; i++) {
                for (j = 0; j < englishSquare[i].length; j++) {
                    if (curCharPos < key.length()) {
                        String curChar = Character.toString(key.charAt(curCharPos));
                        if (curChar.equals("I") || curChar.equals("J")) {
                            curChar = "I/J";
                        }
                        key_set.add(curChar);
                        table[i][j] = curChar;
                        curCharPos++;
                    } else {
                        String curLetter = englishLetters[curLetterPos];
                        while (key_set.contains(curLetter)) {
                            curLetterPos++;
                            curLetter = englishLetters[curLetterPos];
                        }
                        table[i][j] = curLetter;
                        curLetterPos++;
                    }
                }
            }

            return table;

        } else {
            throw new Exception("Key should contain unique letters");
        }
    }

    private static int[] getLetterIdx(String letter, String[][] table) throws Exception {
        for (int i = 0; i < table.length; i++) {
            for (int j = 0; j < table[i].length; j++) {
                if (table[i][j].contains(letter)) {
                    return new int[]{i, j};
                }
            }
        }
        throw new Exception("Unexpected letter " + letter);
    }

    private static boolean keyHasUniqueLetters(String key) {
        HashSet<Character> chars = new HashSet<>();
        for (int i = 0; i < key.length(); i++) {
            chars.add(key.charAt(i));
        }

        return chars.size() == key.length();
    }
}
