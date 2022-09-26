package org.whywolk.crypto;

import org.whywolk.crypto.lab1.PolybiusSquare;
import org.whywolk.crypto.lab2.XORCipher;

public class Main {

    public static void main(String[] args) {
        lab1();
        lab2();
    }

    private static void lab1() {
        System.out.println("_______Lab_1_______");
        String name = "SHIRSHOVALEXEYALEXANDROVICH";
        String university = "NIZHNIYNOVGORODTECHNICALUNIVERSITY";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        try {
            String nameEnc = PolybiusSquare.encrypt(name, "");
            String universityEnc = PolybiusSquare.encrypt(university, "");
            System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

            String nameDec = PolybiusSquare.decrypt(nameEnc, "");
            String universityDec = PolybiusSquare.decrypt(universityEnc, "");
            System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void lab2() {
        System.out.println("_______Lab_2_______");
        String name = "Shirshov Alexey Alexandrovich すごい!!!!";
        String university = "Nizhniy Novgorod Technical University";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        try {
            String nameEnc = XORCipher.encrypt(name, "pass");
            String universityEnc = XORCipher.encrypt(university, "スッパシクレっと1234");
            System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

            String nameDec = XORCipher.decrypt(nameEnc, "pass");
            String universityDec = XORCipher.decrypt(universityEnc, "スッパシクレっと1234");
            System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
