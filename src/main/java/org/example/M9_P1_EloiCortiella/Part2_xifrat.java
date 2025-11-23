package org.example.M9_P1_EloiCortiella;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

public class Part2_xifrat {

    public static void main(String[] args) {
        try {
            Crypto criptografia = new Crypto();

            // Se genera un parell de claus RSA (pública i privada)
            KeyPair parellClausRSA = criptografia.randomGenerate(2048);
            PrivateKey clauPrivada = parellClausRSA.getPrivate();
            PublicKey clauPublica = parellClausRSA.getPublic();

            // Se desa la clau privada a un fitxer
            try (FileOutputStream sortidaPrivada = new FileOutputStream("clau_privada.bin")) {
                sortidaPrivada.write(clauPrivada.getEncoded());
            }

            // Clau simètrica usada a la Part1
            File fitxerClau = new File("clau_simetrica.bin");
            if (!fitxerClau.exists()) {
                System.err.println("EL fitxer 'clau_simetrica.bin' no existeix");
                return;
            }

            FileInputStream entradaClau = new FileInputStream(fitxerClau);
            byte[] bytesClau = entradaClau.readAllBytes();
            entradaClau.close();

            // Reconstruïm la clau simètrica AES
            SecretKey clauSimetrica = new SecretKeySpec(bytesClau, "AES");

            // Xifratge de la clau simètrica amb la clau pública en format RSA
            byte[] clauSimetricaXifrada = criptografia.encryptData(clauSimetrica.getEncoded(), clauPublica);

            // Desa la clau simètrica xifrada a fitxer
            try (FileOutputStream sortidaSimetrica = new FileOutputStream("clau_xifrada.bin")) {
                sortidaSimetrica.write(clauSimetricaXifrada);
            }

            System.out.println("Procés completat correctament: clau privada i clau simètrica xifrades desades.");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
