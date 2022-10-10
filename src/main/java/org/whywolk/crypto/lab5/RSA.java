package org.whywolk.crypto.lab5;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class RSA {

    /**
     * @param message open message
     * @param publicKey String[], where [0] - e, [1] - n
     * @return encrypted message in hex string
     */
    public static String encrypt(String message, String[] publicKey) {
        int len = publicKey[0].length() - 2;
        if (len % 8 != 0) throw new RuntimeException("Key length should be multiple 8");

        // split keys
        BigInteger e = keyFromHex(publicKey[0]);
        BigInteger n = keyFromHex(publicKey[1]);

        // message to hex
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder();
        for (byte b: messageBytes) {
            hex.append(String.format("%02x", b));
        }
        message = hex.toString();

        // encrypt every len size block
        StringBuilder encMessage = new StringBuilder();
        while (message.length() != 0) {

            // get block
            int size = Math.min(message.length(), len/2);
            String block = message.substring(0, size);
            message = message.substring(size);

            // encrypt block
            BigInteger enc = encrypt(new BigInteger(block, 16), e, n);

            // add encrypted block to encrypted message
            encMessage.append(String.format("%0" + (len) + "x", enc));
        }

        return encMessage.toString();
    }

    /**
     * @param message encrypted message in hex string
     * @param privateKey String[], where [0] - d, [1] - n
     * @return open message
     */
    public static String decrypt(String message, String[] privateKey) {
        int len = privateKey[0].length() - 2;
        if (len % 8 != 0) throw new RuntimeException("Key length should be multiple 8");

        // split keys
        BigInteger d = keyFromHex(privateKey[0]);
        BigInteger n = keyFromHex(privateKey[1]);

        // decrypt every len size block
        StringBuilder decMessage = new StringBuilder();
        while (message.length() != 0) {

            // get block
            int size = Math.min(message.length(), len);
            String block = message.substring(0, size);
            message = message.substring(size);

            // decrypt block
            BigInteger dec = decrypt(new BigInteger(block, 16), d, n);
            byte[] b = dec.toByteArray();

            // for other symbols in UTF Biginteger.toByteArray() adds '0' at [0]
            // so it's necessary to remove it
            if (b[0] == 0) {
                b = Arrays.copyOfRange(b, 1, b.length);
            }

            // add decrypted block to message
            decMessage.append(new String(b, StandardCharsets.UTF_8));
        }

        return decMessage.toString();
    }

    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return message.modPow(e, n);
    }

    public static BigInteger decrypt(BigInteger message, BigInteger d, BigInteger n) {
        return message.modPow(d, n);
    }

    public static BigInteger keyFromHex(String key) {
        return new BigInteger(key, 16);
    }

    public static String keyToHex(BigInteger key, int bitLength) {
        return String.format("%0+" + (bitLength/2 + 2) + "x", key);
    }


    /**
     * @param bitLength
     * @return String[][], where
     * String[0] - public key
     * String[1] - private key
     */
    public static String[][] getKeys(int bitLength) {
        if (bitLength % 8 != 0) throw new RuntimeException("Key length should be multiple 8");
        BigInteger[] keys = generateKeys(bitLength);
        String[] publicKey = new String[] {keyToHex(keys[0], bitLength), keyToHex(keys[1], bitLength)};
        String[] privateKey = new String[] {keyToHex(keys[2], bitLength), keyToHex(keys[3], bitLength)};
        return new String[][] {publicKey, privateKey};
    }

    /**
     * @param bitLength
     * @return Biginteger[], where
     * Biginteger[0] - public exponent e
     * Biginteger[1], [4] - module n
     * Biginteger[2] - private exponent d
     */
    public static BigInteger[] generateKeys(int bitLength) {
        // 1. Generate p and q primes
        BigInteger p = RSA.generatePrime(bitLength);
        BigInteger q = RSA.generatePrime(bitLength);

        // 2. Find multiplication of p and q
        BigInteger n = p.multiply(q);

        // 3. Find Euler's totient function
        // fi(n) = (p - 1) * (q - 1)
        BigInteger fi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // 4. Generate int e (1 < e < fi(n)) and co-prime with fi(n)
        // e - public exponent
        BigInteger e = generateE(fi, bitLength);

        // 5. Generate int d that Modular multiplicative inverse to e mod fi
        // d * e = 1 (mod fi(n))
        BigInteger d = extendedGcd(e, fi)[1];

        return new BigInteger[] { e, n, d, n };
    }

    // get larg prime
    private static BigInteger generatePrime(int bitLength) {
        Random r = new Random();
        return BigInteger.probablePrime(bitLength, r);
    }

    // Generate int e (1 < e < fi(n)) and co-prime with fi(n)
    private static BigInteger generateE(BigInteger fi, int bitLength) {
        Random r = new Random();
        BigInteger e;
        do {
            e = new BigInteger(fi.bitLength(), r);

            // if e == 1 or e > fi(n) then generate new e
            while (e.equals(BigInteger.ONE) || (e.compareTo(fi) > 0)) {
                e = new BigInteger(fi.bitLength(), r);
            }
        } while (! gcd(e, fi).equals(BigInteger.ONE));
        return e;
    }

    // Non-recursive implementation of Euclid's algorithm
    // for finding greatest common divisor (gcd)
    private static BigInteger gcd(BigInteger a, BigInteger b) {
        BigInteger tmp;
        while (! b.equals(BigInteger.ZERO)) {
            tmp = a.mod(b);
            a = b;
            b = tmp;
        }
        return a;
    }

    // Extended Euclid's algorithm
    // return array [d, p, q] such that d = gcd(a, b), ap + bq = d
    private static BigInteger[] extendedGcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) return new BigInteger[] { a, BigInteger.ONE, BigInteger.ZERO };

        BigInteger[] vals = extendedGcd(b, a.mod(b));
        BigInteger d = vals[0];
        BigInteger p = vals[2];
        BigInteger q = vals[1].subtract(a.divide(b).multiply(vals[2]));
        return new BigInteger[] { d, p, q };
    }
}
