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
import java.util.Arrays;

/**
 * Comprehensive test class demonstrating the differences between
 * Message Digest, MAC, and HMAC cryptographic concepts.
 */
@DisplayName("Cryptographic Comparison Tests")
class CryptographicComparisonTest {

    @BeforeAll
    static void setUpTink() throws Exception {
        MacConfig.register();
    }

    // ============================================================================
    // MESSAGE DIGEST (Hash Function) Tests
    // ============================================================================

    @Test
    @DisplayName("Message Digest: Should be deterministic and keyless")
    void messageDigestShouldBeDeterministicAndKeyless() {
        // Given
        String message = "Hello, World!";
        byte[] data = message.getBytes();
        
        // When
        String hash1 = createMessageDigest(data);
        String hash2 = createMessageDigest(data);
        
        // Then
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64); // SHA-256 produces 32 bytes = 64 hex chars
        assertThat(hash1).matches("^[a-f0-9]{64}$");
        
        System.out.println("=== Message Digest (SHA-256) ===");
        System.out.println("Input: " + message);
        System.out.println("Hash: " + hash1);
        System.out.println("Deterministic: " + hash1.equals(hash2));
        System.out.println("Key Required: No");
    }

    @Test
    @DisplayName("Message Digest: Should detect any data change")
    void messageDigestShouldDetectDataChanges() {
        // Given
        String original = "Hello, World!";
        String modified = "Hello, World!!"; // Extra exclamation mark
        
        // When
        String originalHash = createMessageDigest(original.getBytes());
        String modifiedHash = createMessageDigest(modified.getBytes());
        
        // Then
        assertThat(originalHash).isNotEqualTo(modifiedHash);
        
        System.out.println("=== Message Digest - Data Change Detection ===");
        System.out.println("Original: " + original + " → " + originalHash);
        System.out.println("Modified: " + modified + " → " + modifiedHash);
        System.out.println("Hashes different: " + !originalHash.equals(modifiedHash));
    }

    @Test
    @DisplayName("Message Digest: Should handle empty and large data")
    void messageDigestShouldHandleVariousDataSizes() {
        // Given
        byte[] emptyData = new byte[0];
        byte[] largeData = new byte[10000]; // 10KB of zeros
        Arrays.fill(largeData, (byte) 0);
        
        // When
        String emptyHash = createMessageDigest(emptyData);
        String largeHash = createMessageDigest(largeData);
        
        // Then
        assertThat(emptyHash).hasSize(64);
        assertThat(largeHash).hasSize(64);
        
        // Known SHA-256 of empty string
        String expectedEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertThat(emptyHash).isEqualTo(expectedEmptyHash);
        
        System.out.println("=== Message Digest - Data Size Handling ===");
        System.out.println("Empty data hash: " + emptyHash);
        System.out.println("Large data hash: " + largeHash);
        System.out.println("Both same length: " + (emptyHash.length() == largeHash.length()));
    }

    // ============================================================================
    // MAC (Message Authentication Code) Tests
    // ============================================================================

    @Test
    @DisplayName("MAC: Should require a key and provide authentication")
    void macShouldRequireKeyAndProvideAuthentication() {
        // Given
        String message = "Authenticated message";
        byte[] data = message.getBytes();
        byte[] key1 = "secretKey1".getBytes();
        byte[] key2 = "secretKey2".getBytes();
        
        // When
        String mac1 = createSimpleMac(data, key1);
        String mac2 = createSimpleMac(data, key2);
        String mac3 = createSimpleMac(data, key1); // Same key as mac1
        
        // Then
        assertThat(mac1).isNotEqualTo(mac2); // Different keys = different MACs
        assertThat(mac1).isEqualTo(mac3);     // Same key = same MAC
        
        System.out.println("=== MAC (Simple Implementation) ===");
        System.out.println("Input: " + message);
        System.out.println("MAC with key1: " + mac1);
        System.out.println("MAC with key2: " + mac2);
        System.out.println("MAC with key1 again: " + mac3);
        System.out.println("Different keys produce different MACs: " + !mac1.equals(mac2));
        System.out.println("Same key produces same MAC: " + mac1.equals(mac3));
    }

    @Test
    @DisplayName("MAC: Should verify both integrity and authenticity")
    void macShouldVerifyIntegrityAndAuthenticity() {
        // Given
        String originalMessage = "Secure message";
        String tamperedMessage = "Secure message!";
        byte[] key = "mySecretKey".getBytes();
        
        // When
        String originalMac = createSimpleMac(originalMessage.getBytes(), key);
        String tamperedMac = createSimpleMac(tamperedMessage.getBytes(), key);
        
        // Then
        assertThat(originalMac).isNotEqualTo(tamperedMac);
        
        System.out.println("=== MAC - Integrity and Authenticity ===");
        System.out.println("Original: " + originalMessage + " → " + originalMac);
        System.out.println("Tampered: " + tamperedMessage + " → " + tamperedMac);
        System.out.println("MACs different (integrity preserved): " + !originalMac.equals(tamperedMac));
    }

    // ============================================================================
    // HMAC (Hash-based Message Authentication Code) Tests
    // ============================================================================

    @Test
    @DisplayName("HMAC: Should use Tink's secure implementation")
    void hmacShouldUseTinkSecureImplementation() {
        // Given
        String message = "HMAC authenticated message";
        byte[] data = message.getBytes();
        
        // When
        String hmac1 = createHmac(data);
        String hmac2 = createHmac(data);
        
        // Then
        assertThat(hmac1).hasSize(74); // Tink HMAC-SHA256 produces 37 bytes = 74 hex chars
        assertThat(hmac1).matches("^[a-f0-9]{74}$");
        assertThat(hmac1).isNotEqualTo(hmac2); // Different random keys each time
        
        System.out.println("=== HMAC (Tink Implementation) ===");
        System.out.println("Input: " + message);
        System.out.println("HMAC 1: " + hmac1);
        System.out.println("HMAC 2: " + hmac2);
        System.out.println("Length: " + hmac1.length() + " characters");
        System.out.println("Different each time (random keys): " + !hmac1.equals(hmac2));
    }

    @Test
    @DisplayName("HMAC: Should provide highest security level")
    void hmacShouldProvideHighestSecurityLevel() {
        // Given
        String message = "High security message";
        byte[] data = message.getBytes();
        
        // When
        String hmac = createHmac(data);
        
        // Then
        assertThat(hmac).isNotNull();
        assertThat(hmac).hasSize(74);
        
        System.out.println("=== HMAC - Security Features ===");
        System.out.println("Input: " + message);
        System.out.println("HMAC: " + hmac);
        System.out.println("Security features:");
        System.out.println("  - Uses cryptographic hash function (SHA-256)");
        System.out.println("  - Combines with secret key");
        System.out.println("  - Resistant to length extension attacks");
        System.out.println("  - Standardized algorithm");
        System.out.println("  - Tink provides secure key management");
    }

    // ============================================================================
    // COMPARISON Tests
    // ============================================================================

    @Test
    @DisplayName("Comparison: Should demonstrate security hierarchy")
    void comparisonShouldDemonstrateSecurityHierarchy() {
        // Given
        String message = "Compare me";
        byte[] data = message.getBytes();
        byte[] key = "testKey".getBytes();
        
        // When
        String messageDigest = createMessageDigest(data);
        String mac = createSimpleMac(data, key);
        String hmac = createHmac(data);
        
        // Then
        assertThat(messageDigest).hasSize(64);
        assertThat(mac).hasSize(64); // Our simple MAC uses SHA-256
        assertThat(hmac).hasSize(74); // Tink HMAC includes key info
        
        System.out.println("=== Security Hierarchy Comparison ===");
        System.out.println("Input: " + message);
        System.out.println("Message Digest: " + messageDigest + " (64 chars)");
        System.out.println("MAC: " + mac + " (64 chars)");
        System.out.println("HMAC: " + hmac + " (74 chars)");
        System.out.println();
        System.out.println("Security Level: Message Digest < MAC < HMAC");
        System.out.println("Features:");
        System.out.println("  Message Digest: Integrity only, no key");
        System.out.println("  MAC: Integrity + Authentication, requires key");
        System.out.println("  HMAC: Integrity + Authentication + Standardized + Secure");
    }

    @Test
    @DisplayName("Comparison: Should show use case differences")
    void comparisonShouldShowUseCaseDifferences() {
        System.out.println("=== Use Case Comparison ===");
        System.out.println();
        System.out.println("Message Digest Use Cases:");
        System.out.println("  ✓ File integrity verification");
        System.out.println("  ✓ Digital fingerprints");
        System.out.println("  ✓ Password storage (with salt)");
        System.out.println("  ✓ Blockchain transactions");
        System.out.println("  ✓ Data deduplication");
        System.out.println();
        System.out.println("MAC Use Cases:");
        System.out.println("  ✓ Authenticated data transmission");
        System.out.println("  ✓ API request signing");
        System.out.println("  ✓ Secure communication protocols");
        System.out.println("  ✓ Custom authentication schemes");
        System.out.println();
        System.out.println("HMAC Use Cases:");
        System.out.println("  ✓ JWT token signing");
        System.out.println("  ✓ API authentication");
        System.out.println("  ✓ Secure protocols (TLS, SSH)");
        System.out.println("  ✓ Digital signatures");
        System.out.println("  ✓ OAuth 2.0");
        System.out.println("  ✓ Any scenario requiring maximum security");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    /**
     * Creates a SHA-256 message digest (hash function).
     * No key required, deterministic output.
     */
    private String createMessageDigest(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Creates a simple MAC using SHA-256 with a key.
     * This is a simplified implementation for demonstration.
     */
    private String createSimpleMac(byte[] data, byte[] key) {
        try {
            // Simple MAC: hash(key || data)
            byte[] combined = new byte[key.length + data.length];
            System.arraycopy(key, 0, combined, 0, key.length);
            System.arraycopy(data, 0, combined, key.length, data.length);
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] mac = digest.digest(combined);
            return bytesToHex(mac);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Creates HMAC using Google Tink's secure implementation.
     * Uses HMAC-SHA256 with automatic key management.
     */
    private String createHmac(byte[] data) {
        try {
            KeysetHandle keysetHandle = KeysetHandle.generateNew(HmacKeyManager.hmacSha256Template());
            Mac mac = keysetHandle.getPrimitive(Mac.class);
            byte[] hmac = mac.computeMac(data);
            return bytesToHex(hmac);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create HMAC with Tink", e);
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
}
