package org.example.M9_P4_EloiCortiella;

import org.example.M9_P2_EloiCortiella.Crypto;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

public class GestorClaus {

    // Constants adaptades a la P4 (canvia nom si cal)
    private static final String KEYSTORE_PATH = "M9_P3_EloiCortiella.ks"; // fitxer del keystore
    private static final String KEYSTORE_PASSWORD = "123456";             // storepass
    private static final String KEY_ALIAS = "myKeys";                     // -alias del keytool
    private static final String KEY_PASSWORD = "654321";                  // keypass

    public static void main(String[] args) {
        try {
            Crypto crypto = new Crypto();

            // Carregar el keystore
            System.out.println("Carregant keystore: " + KEYSTORE_PATH);
            KeyStore ks = crypto.loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD);

            // Obtenir clau pública i privada a partir de l'àlies
            if (!ks.containsAlias(KEY_ALIAS)) {
                System.err.println("No s'ha trobat l'àlies '" + KEY_ALIAS + "' al keystore.");
                return;
            }

            // Certificat associat a l'àlies → d'aquí traiem la clau pública
            Certificate certEntrada = ks.getCertificate(KEY_ALIAS);
            if (certEntrada == null) {
                System.err.println("No hi ha certificat associat a l'àlies '" + KEY_ALIAS + "'.");
                return;
            }
            PublicKey clauPublica = certEntrada.getPublicKey();

            // Clau privada associada a l'àlies (cal password de la clau)
            Key key = ks.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
            if (!(key instanceof PrivateKey)) {
                System.err.println("L'àlies '" + KEY_ALIAS + "' no té una clau privada associada.");
                return;
            }
            PrivateKey clauPrivada = (PrivateKey) key;

            System.out.println("Claus carregades correctament des del keystore.");

            // Generar el cos del certificat (amb la clau pública en Base64)
            String cosCertificat = generarCosCertificat(clauPublica);

            // Signar el cos del certificat amb la clau privada
            byte[] signatura = crypto.signData(
                    cosCertificat.getBytes(StandardCharsets.UTF_8),
                    clauPrivada
            );

            // 5) Desa el cos i la signatura en fitxers
            guardarCertificatICodi(cosCertificat, signatura);

            System.out.println("✔ Certificat generat i signat correctament.");
            System.out.println("   - Cos: certificat_M9_P4_EloiCortiella.txt");
            System.out.println("   - Signatura (Base64): certificat_M9_P4_EloiCortiella.sig");

        } catch (Exception e) {
            System.err.println("❌ Error a GestorClaus: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Construeix el cos del certificat afegint la clau pública en Base64.
     */
    private static String generarCosCertificat(PublicKey clauPublica) {
        String clauPublicaBase64 = Base64.getEncoder()
                .encodeToString(clauPublica.getEncoded());

        StringBuilder sb = new StringBuilder();
        sb.append("=== CERTIFICAT DIGITAL M9_P4 ===\n");
        sb.append("Alumne: Eloi Cortiella\n");
        sb.append("Cicle: DAM2 - Programació de Serveis i Processos\n");
        sb.append("Assignatura: M9 - PSP (Seguretat i Criptografia)\n\n");

        sb.append("CLAU PUBLICA (Base64):\n");
        sb.append(clauPublicaBase64).append("\n");

        return sb.toString();
    }

    /**
     * Desa el cos del certificat i la signatura en fitxers.
     */
    private static void guardarCertificatICodi(String cosCertificat, byte[] signatura) throws Exception {
        // Cos del certificat en text pla
        try (FileOutputStream fos = new FileOutputStream("certificat_M9_P4_EloiCortiella.txt")) {
            fos.write(cosCertificat.getBytes(StandardCharsets.UTF_8));
        }

        // Signatura en Base64 per poder veure-la bé com a text
        String signaturaBase64 = Base64.getEncoder().encodeToString(signatura);
        try (FileOutputStream fos = new FileOutputStream("certificat_M9_P4_EloiCortiella.sig")) {
            fos.write(signaturaBase64.getBytes(StandardCharsets.UTF_8));
        }
    }
}
