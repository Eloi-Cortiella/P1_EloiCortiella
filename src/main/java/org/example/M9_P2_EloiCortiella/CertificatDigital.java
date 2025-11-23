package org.example.M9_P2_EloiCortiella;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class CertificatDigital {
    private static final String DN =
            "CN=Eloi Cortiella, OU=DAM2, O=Institut, L=Tarragona, ST=Catalunya, C=ES";

    public static void main(String[] args) throws Exception {
        Crypto crypto = new Crypto();

        // 1) Claus
        KeyPair kp = crypto.randomGenerate(2048);
        PublicKey pub = kp.getPublic();
        PrivateKey prv = kp.getPrivate();

        // 2) Firma/validació (segons teoria)
        byte[] dades = "Missatge de prova per signar".getBytes(StandardCharsets.UTF_8);
        byte[] sig = crypto.signData(dades, prv);
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(sig));
        System.out.println("Signature valid: " + crypto.validateSignature(dades, sig, pub));

        // 3) X.509 auto-signat (BC)
        X509Certificate cert = selfSigned(kp, DN, 365);

        // 4) Desa .CER (DER)
        try (FileOutputStream fos = new FileOutputStream(
                "src/main/java/org/example/M9_P2_EloiCortiella/M9_P2_EloiCortiella.CER")) {
            fos.write(cert.getEncoded());
        }

        // 5) Verifica certificat
        cert.verify(pub);
        System.out.println("Certificat OK → " + cert.getSubjectX500Principal());
    }

    private static X509Certificate selfSigned(KeyPair kp, String dn, int days) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000);
        Date notAfter  = new Date(now + days * 24L * 60 * 60 * 1000L);

        X500Name subject = new X500Name(dn);
        BigInteger serial = new BigInteger(64, new SecureRandom());
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, spki
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
