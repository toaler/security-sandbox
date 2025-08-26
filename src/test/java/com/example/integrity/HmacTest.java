package com.example.integrity;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import static org.assertj.core.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Test class demonstrating Google Tink's HMAC functionality.
 */
@DisplayName("HMAC Tests")
class HmacTest {

    @BeforeAll
    static void setUpTink() throws Exception {
        MacConfig.register();
    }

    /**
     * Generates SHA-256 hash using standard Java crypto for deterministic hashing.
     */
    private String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Generates HMAC-SHA256 using Google Tink.
     */
    private String hmacSha256(byte[] content) {
        try {
            KeysetHandle keysetHandle = KeysetHandle.generateNew(HmacKeyManager.hmacSha256Template());
            Mac mac = keysetHandle.getPrimitive(Mac.class);
            byte[] macBytes = mac.computeMac(content);
            return bytesToHex(macBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute HMAC-SHA256 with Tink", e);
        }
    }

    /**
     * Converts a byte array to a hexadecimal string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    @Test
    @DisplayName("Should demonstrate difference between SHA-256 and HMAC-SHA256")
    void shouldDemonstrateDifferenceBetweenSha256AndHmac() {
        // Given
        String testData = "Hello, Security Sandbox!";
        byte[] dataBytes = testData.getBytes();
        
        // When
        String sha256Hash = sha256(dataBytes);
        String hmacSha256Result = hmacSha256(dataBytes);
        
        // Then
        assertThat(sha256Hash).isNotNull().hasSize(64);
        assertThat(hmacSha256Result).isNotNull().hasSize(74); // HMAC-SHA256 with Tink produces 37 bytes = 74 hex chars
        
        System.out.println("SHA-256 hash: " + sha256Hash);
        System.out.println("HMAC-SHA256: " + hmacSha256Result);
        System.out.println("Note: HMAC-SHA256 includes key information, making it longer");
    }

    @Test
    @DisplayName("Should show SHA-256 is deterministic while HMAC-SHA256 uses random keys")
    void shouldShowSha256IsDeterministicWhileHmacUsesRandomKeys() {
        // Given
        String testData = "Consistent test data";
        byte[] dataBytes = testData.getBytes();
        
        // When - SHA-256 should be identical
        String sha256Hash1 = sha256(dataBytes);
        String sha256Hash2 = sha256(dataBytes);
        
        // And - HMAC-SHA256 should be different due to random key generation
        String hmacSha256_1 = hmacSha256(dataBytes);
        String hmacSha256_2 = hmacSha256(dataBytes);
        
        // Then
        assertThat(sha256Hash1).isEqualTo(sha256Hash2);
        assertThat(hmacSha256_1).isNotEqualTo(hmacSha256_2);
        
        System.out.println("SHA-256 (deterministic):");
        System.out.println("  First call:  " + sha256Hash1);
        System.out.println("  Second call: " + sha256Hash2);
        System.out.println("  Identical: " + sha256Hash1.equals(sha256Hash2));
        
        System.out.println("HMAC-SHA256 (random keys):");
        System.out.println("  First call:  " + hmacSha256_1);
        System.out.println("  Second call: " + hmacSha256_2);
        System.out.println("  Identical: " + hmacSha256_1.equals(hmacSha256_2));
    }

    @Test
    @DisplayName("Should demonstrate Tink's key management capabilities")
    void shouldDemonstrateTinkKeyManagement() {
        // Given
        String testData = "Data to authenticate";
        byte[] dataBytes = testData.getBytes();
        
        // When
        String hmacResult = hmacSha256(dataBytes);
        
        // Then
        assertThat(hmacResult).isNotNull().hasSize(74);
        
        System.out.println("Tink HMAC-SHA256 result: " + hmacResult);
        System.out.println("This demonstrates Tink's automatic key generation and management");
        System.out.println("The result includes both the MAC and key information");
    }

    @Test
    @DisplayName("Should show use cases for different hash types")
    void shouldShowUseCasesForDifferentHashTypes() {
        // Given
        String sensitiveData = "Sensitive information that needs integrity verification";
        byte[] dataBytes = sensitiveData.getBytes();
        
        // When
        String sha256ForIntegrity = sha256(dataBytes);
        String hmacForAuthentication = hmacSha256(dataBytes);
        
        // Then
        assertThat(sha256ForIntegrity).hasSize(64);
        assertThat(hmacForAuthentication).hasSize(74);
        
        System.out.println("=== Use Case Comparison ===");
        System.out.println("SHA-256 (Data Integrity):");
        System.out.println("  - Use case: Verify data hasn't been tampered with");
        System.out.println("  - Deterministic: Same input always produces same output");
        System.out.println("  - Example: " + sha256ForIntegrity);
        System.out.println("  - Length: " + sha256ForIntegrity.length() + " characters");
        
        System.out.println("HMAC-SHA256 (Authentication):");
        System.out.println("  - Use case: Authenticate data with a secret key");
        System.out.println("  - Key-based: Requires a secret key for verification");
        System.out.println("  - Example: " + hmacForAuthentication);
        System.out.println("  - Length: " + hmacForAuthentication.length() + " characters");
        
        System.out.println("=== Tink Integration ===");
        System.out.println("Tink provides:");
        System.out.println("  - Secure key generation");
        System.out.println("  - Key management");
        System.out.println("  - Cryptographic primitives");
        System.out.println("  - Protection against common cryptographic mistakes");
    }
}
