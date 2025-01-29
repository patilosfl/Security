
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

public class JwtWithP12 {
    private static final String P12_FILE_PATH = "path/to/your/certificate.p12"; // Update with actual path
    private static final String KEYSTORE_PASSWORD = "changeit"; // Update with actual password
    private static final String ALIAS = "your-key-alias"; // Update with actual alias

    // Load Private Key from PKCS12 (.p12) file
    private static PrivateKey getPrivateKey() throws Exception {
        FileInputStream fis = new FileInputStream(P12_FILE_PATH);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());

        Key key = keyStore.getKey(ALIAS, KEYSTORE_PASSWORD.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new RuntimeException("Private key not found in keystore");
    }

    // Load Public Key from PKCS12 (.p12) file
    private static PublicKey getPublicKey() throws Exception {
        FileInputStream fis = new FileInputStream(P12_FILE_PATH);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());

        Certificate cert = keyStore.getCertificate(ALIAS);
        if (cert != null) {
            return cert.getPublicKey();
        }
        throw new RuntimeException("Public key not found in keystore");
    }

    // Generate JWT Token using Private Key (SHA256withRSA)
    public static String generateJwtToken() throws Exception {
        PrivateKey privateKey = getPrivateKey();

        return Jwts.builder()
                .setSubject("user123")
                .setIssuer("my-app")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour expiry
                .signWith(privateKey, Jwts.SIG.RS256) // SHA256withRSA algorithm
                .compact();
    }

    // Validate JWT Token using Public Key
    public static void validateJwtToken(String token) throws Exception {
        PublicKey publicKey = getPublicKey();

        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(publicKey) // Verify with public key
                    .build()
                    .parseSignedClaims(token);

            System.out.println("JWT is valid. Claims: " + claimsJws.getPayload());
        } catch (JwtException e) {
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

