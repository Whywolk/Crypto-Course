package org.whywolk.crypto.lab5;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class RSA {

    public static String encrypt(String message, String[] publicKey) {
        int len = publicKey[0].length() - 2;
//        if (message.length()*2 >= len) throw new RuntimeException("Message length should be lesser than key length");

        BigInteger e = keyFromHex(publicKey[0]);
        BigInteger n = keyFromHex(publicKey[1]);

        StringBuilder encMessage = new StringBuilder();
        while (message.length() != 0) {
            int size = Math.min(message.length(), len/2 - 1);
            String tmp = message.substring(0, size);
            message = message.substring(size);
            BigInteger enc = encrypt(new BigInteger(tmp.getBytes(StandardCharsets.UTF_8)), e, n);
            encMessage.append(String.format("%0" + (len) + "x", enc));
        }

        return encMessage.toString();
    }

    public static String decrypt(String message, String[] privateKey) {
        int len = privateKey[0].length() - 2;
//        if (message.length() > len) throw new RuntimeException("Message length should be lesser than key length");

        BigInteger d = keyFromHex(privateKey[0]);
        BigInteger n = keyFromHex(privateKey[1]);

        StringBuilder decMessage = new StringBuilder();
        while (message.length() != 0) {
            int size = Math.min(message.length(), len);
            String tmp = message.substring(0, size);
            message = message.substring(size);
            BigInteger dec = decrypt(new BigInteger(tmp, 16), d, n);
            decMessage.append(new String(dec.toByteArray(), StandardCharsets.UTF_8));
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

    public static String[][] getKeys(int bitLength) {
        BigInteger[] keys = generateKeys(bitLength);
        String[] publicKey = new String[] {keyToHex(keys[0], bitLength), keyToHex(keys[1], bitLength)};
        String[] privateKey = new String[] {keyToHex(keys[2], bitLength), keyToHex(keys[3], bitLength)};
        return new String[][] {publicKey, privateKey};
    }

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
