package org.example.M9_P1_EloiCortiella;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.*;

public class Part1_xifrat {

    public static void main(String[] args) {
        try {
            Crypto criptografia = new Crypto();

            // Paraula de pas
            Console consola = System.console();
            char[] contrasenyaChars = consola.readPassword("Introdueix la paraula de pas: ");
            String contrasenya = new String(contrasenyaChars);

            // Generar una sal
            byte[] sal = new byte[16];
            SecureRandom aleatori = new SecureRandom();
            aleatori.nextBytes(sal);

            // Clau simètrica AES i la sal
            String contrasenyaAmbSal = contrasenya + Base64.getEncoder().encodeToString(sal);
            SecretKey clauSimetrica = criptografia.passwordKeyGeneration(contrasenyaAmbSal, 256);

            try (FileOutputStream sortidaClau = new FileOutputStream("clau_simetrica.bin")) {
                sortidaClau.write(clauSimetrica.getEncoded());
            }

            // Llegeix el fitxer en clar
            FileInputStream entradaFitxer = new FileInputStream("./src/main/resources/Text_en_clar.txt");
            byte[] textClar = entradaFitxer.readAllBytes();
            entradaFitxer.close();

            // Xifrar el fitxer
            byte[] textXifrat = criptografia.encryptDataCBC(clauSimetrica, textClar);

            // Desar al Text_xifrat.bin
            try (FileOutputStream sortidaFitxer = new FileOutputStream("Text_xifrat.bin")) {
                sortidaFitxer.write(sal);
                sortidaFitxer.write(Crypto.IV_PARAM);
                sortidaFitxer.write(textXifrat);
            }

            System.out.println("Fitxer xifrat correctament.");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
