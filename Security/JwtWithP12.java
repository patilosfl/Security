import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

public class JwtWithP12 {
    private static final String P12_FILE_PATH = "path/to/your/certificate.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String ALIAS = "your-key-alias";

    private static PrivateKey getPrivateKey() throws Exception {
        FileInputStream fis = new FileInputStream(P12_FILE_PATH);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        return (PrivateKey) keyStore.getKey(ALIAS, KEYSTORE_PASSWORD.toCharArray());
    }

    private static PublicKey getPublicKey() throws Exception {
        FileInputStream fis = new FileInputStream(P12_FILE_PATH);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        Certificate cert = keyStore.getCertificate(ALIAS);
        return cert.getPublicKey();
    }

    public static String generateJwtToken() throws Exception {
        PrivateKey privateKey = getPrivateKey();

        return Jwts.builder()
                .setSubject("user123")
                .setIssuer("my-app")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour expiry
                .signWith(privateKey, SignatureAlgorithm.RS256) // Works in JJWT 0.11.x
                .compact();
    }

    public static void validateJwtToken(String token) throws Exception {
        PublicKey publicKey = getPublicKey();

        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(publicKey) // Use setSigningKey in JJWT 0.11.x
                    .build()
                    .parseClaimsJws(token);

            System.out.println("JWT is valid. Claims: " + claimsJws.getBody());
        } catch (Exception e) {
            System.err.println("Invalid JWT: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            String jwtToken = generateJwtToken();
            System.out.println("Generated JWT Token: " + jwtToken);

            validateJwtToken(jwtToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
