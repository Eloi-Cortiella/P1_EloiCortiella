package org.example.M9_P1_EloiCortiella;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class P1_desxifrat {
    public static void main(String[] args) {
        try {
            // Llegeix la clau privada del fitxer clau_privada.bin
            FileInputStream entradaPrivada = new FileInputStream("clau_privada.bin");
            byte[] bytesClauPrivada = entradaPrivada.readAllBytes();
            entradaPrivada.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec especificacioPrivada = new PKCS8EncodedKeySpec(bytesClauPrivada);
            PrivateKey clauPrivada = keyFactory.generatePrivate(especificacioPrivada);

            // Llegeix la clau simètrica xifrada (clau_xifrada.bin)
            FileInputStream entradaXifrada = new FileInputStream("clau_xifrada.bin");
            byte[] bytesClauXifrada = entradaXifrada.readAllBytes();
            entradaXifrada.close();

            // Desxifra la clau simètrica amb la clau privada RSA
            Cipher desxifradorRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            desxifradorRSA.init(Cipher.DECRYPT_MODE, clauPrivada);
            byte[] bytesClauSimetrica = desxifradorRSA.doFinal(bytesClauXifrada);

            // Reconstrueix la clau simètrica (AES)
            SecretKey clauSimetrica = new SecretKeySpec(bytesClauSimetrica, "AES");

            // Llegeix el fitxer de dades xifrades (Text_xifrat.bin)
            FileInputStream entradaDades = new FileInputStream("Text_xifrat.bin");
            byte[] bytesFitxer = entradaDades.readAllBytes();
            entradaDades.close();

            // Separar SAL (16 bytes), IV (16 bytes) i TEXT XIFRAT
            byte[] sal = new byte[16];
            byte[] iv = new byte[16];
            byte[] textXifrat = new byte[bytesFitxer.length - 32];
            System.arraycopy(bytesFitxer, 0, sal, 0, 16);
            System.arraycopy(bytesFitxer, 16, iv, 0, 16);
            System.arraycopy(bytesFitxer, 32, textXifrat, 0, textXifrat.length);

            // Desxifra les dades creant una instancia del Cipher amb AES/CBC/PKCS5Padding
            Cipher desxifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Incialitzem el Cipher amb el mode DECRYPT_MODE
            desxifradorAES.init(Cipher.DECRYPT_MODE, clauSimetrica, new javax.crypto.spec.IvParameterSpec(iv));
            byte[] textDesxifrat = desxifradorAES.doFinal(textXifrat);

            // Desa el text desxifrat a nou fitxer que es diu Text_desxifrat.txt
            try (FileOutputStream sortida = new FileOutputStream("Text_desxifrat.txt")) {
                sortida.write(textDesxifrat);
            }

            System.out.println("Fitxer desxifrat correctament. S'ha creat 'Text_desxifrat.txt'.");

        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}