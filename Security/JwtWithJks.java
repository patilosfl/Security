
package target.classes.com.example;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Base64;

public class JwtWithJks {
    private static final String KEYSTORE_PATH = "path/to/your/keystore.jks"; // Update with actual path
    private static final String KEYSTORE_PASSWORD = "changeit"; // Update with actual password
    private static final String ALIAS = "your-key-alias"; // Update with actual alias
    private static final String KEY_PASSWORD = "changeit"; // Update with actual key password

    // Load Private Key from JKS
    private static PrivateKey getPrivateKey() throws Exception {
        FileInputStream fis = new FileInputStream(KEYSTORE_PATH);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());

        Key key = keyStore.getKey(ALIAS, KEY_PASSWORD.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new RuntimeException("Private key not found in keystore");
    }

    // Load Public Key from JKS
    private static PublicKey getPublicKey() throws Exception {
        FileInputStream fis = new FileInputStream(KEYSTORE_PATH);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());

        Certificate cert = keyStore.getCertificate(ALIAS);
        if (cert != null) {
            return cert.getPublicKey();
        }
        throw new RuntimeException("Public key not found in keystore");
    }

    // Generate JWT Token using Private Key
    public static String generateJwtToken() throws Exception {
        PrivateKey privateKey = getPrivateKey();

        return Jwts.builder()
                .setSubject("user123")
                .setIssuer("my-app")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour expiry
                .signWith(privateKey, Jwts.SIG.RS256) // RS256 algorithm
                .compact();
    }

    // Validate JWT Token using Public Key
    public static void validateJwtToken(String token) throws Exception {
        PublicKey publicKey = getPublicKey();

        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(publicKey) // Validate with public key
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
