package com.example;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Date;

/**
 * Main application class demonstrating the use of Google Tink and Nimbus JOSE+JWT libraries.
 */
public class App {
    
    public static void main(String[] args) {
        System.out.println("Security Sandbox - Java 21 Maven Project");
        System.out.println("========================================");
        
        try {
            // Demonstrate Google Tink encryption
            demonstrateTinkEncryption();
            
            // Demonstrate Nimbus JWT
            demonstrateNimbusJWT();
            
        } catch (Exception e) {
            System.err.println("Error demonstrating libraries: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Demonstrates basic encryption/decryption using Google Tink.
     */
    private static void demonstrateTinkEncryption() throws GeneralSecurityException {
        System.out.println("\n--- Google Tink Encryption Demo ---");
        
        // Initialize Tink
        AeadConfig.register();
        
        // Generate a new key
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AesGcmKeyManager.aes256GcmTemplate());
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        // Encrypt some data
        String plaintext = "Hello, Tink!";
        String associatedData = "context";
        
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(), associatedData.getBytes());
        System.out.println("Encrypted data length: " + ciphertext.length + " bytes");
        
        // Decrypt the data
        byte[] decrypted = aead.decrypt(ciphertext, associatedData.getBytes());
        String decryptedText = new String(decrypted);
        
        System.out.println("Original: " + plaintext);
        System.out.println("Decrypted: " + decryptedText);
        System.out.println("Encryption/Decryption successful: " + plaintext.equals(decryptedText));
    }
    
    /**
     * Demonstrates JWT creation and verification using Nimbus JOSE+JWT.
     */
    private static void demonstrateNimbusJWT() throws JOSEException, ParseException {
        System.out.println("\n--- Nimbus JWT Demo ---");
        
        // Create a JWT claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user123")
                .issuer("security-sandbox")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .claim("role", "admin")
                .build();
        
        // Create a signed JWT (using HMAC for simplicity)
        String secret = "my-secret-key-that-is-long-enough-for-hmac-sha256";
        JWSSigner signer = new MACSigner(secret);
        
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        
        String jwtString = signedJWT.serialize();
        System.out.println("Generated JWT: " + jwtString);
        
        // Parse and verify the JWT
        SignedJWT parsedJWT = SignedJWT.parse(jwtString);
        System.out.println("JWT Subject: " + parsedJWT.getJWTClaimsSet().getSubject());
        System.out.println("JWT Issuer: " + parsedJWT.getJWTClaimsSet().getIssuer());
        System.out.println("JWT Role: " + parsedJWT.getJWTClaimsSet().getClaim("role"));
    }
}
