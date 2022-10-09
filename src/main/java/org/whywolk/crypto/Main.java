package org.whywolk.crypto;

import org.whywolk.crypto.lab1.PolybiusSquare;
import org.whywolk.crypto.lab2.XORCipher;
import org.whywolk.crypto.lab3.EcbDES;
import org.whywolk.crypto.lab4.CbcDES;
import org.whywolk.crypto.lab5.RSA;

public class Main {

    public static void main(String[] args) {
//        lab1();
//        lab2();
//        lab3();
//        lab4();
        lab5();
    }

    private static void lab1() {
        System.out.println("_______Lab_1_______");
        String name = "SHIRSHOVALEXEYALEXANDROVICH";
        String university = "NIZHNIYNOVGORODTECHNICALUNIVERSITY";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        try {
            String nameEnc = PolybiusSquare.encrypt(name, "MYPASWORD");
            String universityEnc = PolybiusSquare.encrypt(university, "SECRT");
            System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

            String nameDec = PolybiusSquare.decrypt(nameEnc, "MYPASWORD");
            String universityDec = PolybiusSquare.decrypt(universityEnc, "SECRT");
            System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void lab2() {
        System.out.println("_______Lab_2_______");
        String name = "Shirshov Alexey Alexandrovich";
        String university = "Nizhniy Novgorod Technical University";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        try {
            String nameEnc = XORCipher.encrypt(name, "pass");
            String universityEnc = XORCipher.encrypt(university, "hard_pass");
            System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

            String nameDec = XORCipher.decrypt(nameEnc, "pass");
            String universityDec = XORCipher.decrypt(universityEnc, "hard_pass");
            System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void lab3() {
        System.out.println("_______Lab_3_______");
        String name = "Shirshov Alexey Alexandrovich";
        String university = "Nizhniy Novgorod Technical University";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        String nameEnc = EcbDES.encrypt(name, "pass1111");
        String universityEnc = EcbDES.encrypt(university, "hard_pas");
        System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

        String nameDec = EcbDES.decrypt(nameEnc, "pass1111");
        String universityDec = EcbDES.decrypt(universityEnc, "hard_pas");
        System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
    }

    private static void lab4() {
        System.out.println("_______Lab_4_______");
        String name = "Shirshov Alexey Alexandrovich";
        String university = "Nizhniy Novgorod Technical University";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        String nameEnc = CbcDES.encrypt(name, "pass1111", "12345678");
        String universityEnc = CbcDES.encrypt(university, "hard_pas", "otherVec");
        System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);
//        nameEnc = nameEnc.substring(0, 17) + "dd" + nameEnc.substring(19);

        String nameDec = CbcDES.decrypt(nameEnc, "pass1111", "12345678");
        String universityDec = CbcDES.decrypt(universityEnc, "hard_pas", "otherVec");
        System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
    }

    private static void lab5() {
        System.out.println("_______Lab_5_______");
        String name = "Shirshov Alexey Alexandrovich";
        String university = "Nizhniy Novgorod Technical University";
        System.out.printf("Original messages: \n\t%s \n\t%s\n", name, university);

        String[] keys = RSA.getKeys(64);
        String publicKey = keys[0];
        String privateKey = keys[1];


        String nameEnc = RSA.encrypt(name, publicKey);
        String universityEnc = RSA.encrypt(university, publicKey);
        System.out.printf("Encrypted: \n\t%s \n\t%s\n", nameEnc, universityEnc);

        String nameDec = RSA.decrypt(nameEnc, privateKey);
        String universityDec = RSA.decrypt(universityEnc, privateKey);
        System.out.printf("Decrypted: \n\t%s \n\t%s\n", nameDec, universityDec);
    }
}
