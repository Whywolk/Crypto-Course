package org.whywolk.crypto.lab5;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Random;

public class RSA {

    public static String encrypt(String message, String publicKey) {
        BigInteger msg = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
        BigInteger[] keys = keyFromHex(publicKey);
        BigInteger e = keys[0];
        BigInteger n = keys[1];
        BigInteger encMessage = encrypt(msg, e, n);
        return encMessage.toString(16);
    }

    public static String decrypt(String message, String privateKey) {
        BigInteger msg = new BigInteger(HexFormat.of().parseHex(message));
        BigInteger[] keys = keyFromHex(privateKey);
        BigInteger d = keys[0];
        BigInteger n = keys[1];
        BigInteger decMessage = decrypt(msg, d, n);
        return new String(decMessage.toByteArray(), StandardCharsets.UTF_8);
    }

    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return message.modPow(e, n);
    }

    public static BigInteger decrypt(BigInteger message, BigInteger d, BigInteger n) {
        return message.modPow(d, n);
    }

    public static BigInteger[] keyFromHex(String key) {
        if (key.length() % 8 != 0) throw new RuntimeException("Keys length should be even");
        String aS = key.substring(0, key.length() / 2);
        String bS = key.substring(key.length() / 2);
        return new BigInteger[] {new BigInteger(aS, 16), new BigInteger(bS, 16)};
    }

    public static String keyToHex(BigInteger a, BigInteger b) {

        StringBuilder aS = new StringBuilder(a.toByteArray());
        StringBuilder bS = new StringBuilder(b.toString(16));

        if (aS.length() != bS.length()) {
            int count = Math.abs(bS.length() - aS.length());
            if (aS.length() < bS.length()) {
                for (int i = 0; i < count; i++) {
                    aS.insert(0, "0");
                }
            } else {
                for (int i = 0; i < count; i++) {
                    bS.insert(0, "0");
                }
            }
        }
        if (aS.length() % 8 != 0) {
            int count = aS.length() % 8;
            for (int i = 0; i < count; i++) {
                aS.insert(0, "0");
                bS.insert(0, "0");
            }
        }
        return aS.append(bS).toString();
    }

    public static String[] getKeys(int bitLength) {
        BigInteger[] keys = generateKeys(bitLength);
        String publicKey = keyToHex(keys[0], keys[1]);
        String privateKey = keyToHex(keys[2], keys[3]);
        return new String[] {publicKey, privateKey};
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
//        BigInteger d = inverse(e, fi);

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
            e = new BigInteger(bitLength * 2, r);

            // if e == 1 or e > fi(n) then generate new e
            while (e.equals(BigInteger.ONE) || (e.compareTo(fi) > 0)) {
                e = new BigInteger(bitLength * 2, r);
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

    //  return p, where ap + bq = d, d = gcd(a, b)
    private static BigInteger inverse(BigInteger a, BigInteger b) {
        BigInteger t = BigInteger.ZERO;
        BigInteger r = a;
        BigInteger newt = BigInteger.ONE;
        BigInteger newr = b;

        while (! newr.equals(BigInteger.ZERO)) {
            BigInteger quotient = r.divide(newr);

            BigInteger tmpNewt = t.subtract(quotient.multiply(newt));
            t = newt;
            newt = tmpNewt;

            BigInteger tmpNewr = r.subtract(quotient.multiply(newr));
            r = newr;
            newr = tmpNewr;
        }
        if (t.compareTo(BigInteger.ZERO) < 0) {
            t = t.add(b);
        }
        return t;
    }
}
