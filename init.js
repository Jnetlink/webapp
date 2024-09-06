import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

public class JKSGenerator {
    public static void main(String alias, String password, int validityDays) throws Exception {
        // Buat KeyPair (kunci publik dan privat)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Membuat sertifikat X509 yang simpel
        X500Principal subject = new X500Principal("CN=JKS Generator, O=My Company");
        X509Certificate certificate = CertificateUtils.generateCertificate(subject, keyPair, validityDays);

        // Simpan ke dalam keystore JKS
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null); // Buat keystore baru
        ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new Certificate[]{certificate});

        // Tulis ke file
        try (FileOutputStream fos = new FileOutputStream(alias + ".jks")) {
            ks.store(fos, password.toCharArray());
        }

        System.out.println("JKS created successfully!");
    }
}
