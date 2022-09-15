package org.whywolk.crypto;

import org.whywolk.crypto.lab1.PolybiusSquare;

public class Main {

    public static void main(String[] args) {
        lab1();
    }

    private static void lab1() {
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
}
