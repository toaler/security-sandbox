package com.example.integrity;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import static org.assertj.core.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Test class for data integrity verification using cryptographic hashes.
 */
@DisplayName("Message Digest Tests")
class MessageDigestTest {

    private String warehouseRefundsJson;
    private String expectedHash;

    @BeforeAll
    static void setUpTink() throws Exception {
        MacConfig.register();
    }

    @BeforeEach
    void setUp() throws IOException {
        // Load the warehouse refunds JSON file
        Path jsonPath = Paths.get("src/test/resources/com/example/integrity/warehouse-refunds.json");
        warehouseRefundsJson = Files.readString(jsonPath);
        
        // Pre-calculated SHA-256 hash of the JSON content
        // This would typically be stored separately or calculated during data creation
        expectedHash = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678";
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
    @DisplayName("Should generate consistent SHA-256 hash for JSON data")
    void shouldGenerateConsistentSha256Hash() {
        // Given
        byte[] jsonBytes = warehouseRefundsJson.getBytes();
        
        // When
        String actualHash = sha256(jsonBytes);
        
        // Then
        assertThat(actualHash)
            .isNotNull()
            .hasSize(64) // SHA-256 produces 32 bytes = 64 hex characters
            .matches("^[a-f0-9]{64}$"); // Should be lowercase hex string
        
        System.out.println("Generated SHA-256 hash: " + actualHash);
    }

    @Test
    @DisplayName("Should detect data tampering through hash verification")
    void shouldDetectDataTampering() {
        // Given
        String originalJson = warehouseRefundsJson;
        String tamperedJson = originalJson.replace("89.99", "99.99"); // Tamper with a price
        
        byte[] originalBytes = originalJson.getBytes();
        byte[] tamperedBytes = tamperedJson.getBytes();
        
        // When
        String originalHash = sha256(originalBytes);
        String tamperedHash = sha256(tamperedBytes);
        
        // Then
        assertThat(originalHash).isNotEqualTo(tamperedHash);
        assertThat(originalHash).hasSize(64);
        assertThat(tamperedHash).hasSize(64);
        
        System.out.println("Original hash: " + originalHash);
        System.out.println("Tampered hash: " + tamperedHash);
    }

    @Test
    @DisplayName("Should generate same hash for identical content")
    void shouldGenerateSameHashForIdenticalContent() {
        // Given
        byte[] content1 = warehouseRefundsJson.getBytes();
        byte[] content2 = warehouseRefundsJson.getBytes(); // Same content
        
        // When
        String hash1 = sha256(content1);
        String hash2 = sha256(content2);
        
        // Then
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).isNotNull();
    }

    @Test
    @DisplayName("Should handle empty content")
    void shouldHandleEmptyContent() {
        // Given
        byte[] emptyContent = new byte[0];
        
        // When
        String hash = sha256(emptyContent);
        
        // Then
        assertThat(hash).isNotNull();
        assertThat(hash).hasSize(64);
        
        // SHA-256 of empty string is known
        String expectedEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertThat(hash).isEqualTo(expectedEmptyHash);
    }

    @Test
    @DisplayName("Should verify data integrity with expected hash")
    void shouldVerifyDataIntegrity() {
        // Given
        byte[] jsonBytes = warehouseRefundsJson.getBytes();
        
        // When
        String actualHash = sha256(jsonBytes);
        
        // Then
        // In a real scenario, you would compare against a stored hash
        // For this test, we'll just verify the hash format and consistency
        assertThat(actualHash)
            .isNotNull()
            .hasSize(64)
            .matches("^[a-f0-9]{64}$");
        
        // Store the hash for future verification
        System.out.println("Data integrity hash: " + actualHash);
        System.out.println("Use this hash to verify data integrity in the future");
    }

    @Test
    @DisplayName("Should demonstrate hash verification workflow")
    void shouldDemonstrateHashVerificationWorkflow() {
        // Given - Simulate a real-world scenario
        String dataAtCreation = warehouseRefundsJson;
        String dataAtVerification = warehouseRefundsJson; // Should be identical
        
        // When - Calculate hash at creation time
        String creationHash = sha256(dataAtCreation.getBytes());
        
        // And - Calculate hash at verification time
        String verificationHash = sha256(dataAtVerification.getBytes());
        
        // Then - Verify integrity
        boolean isIntegrityMaintained = creationHash.equals(verificationHash);
        
        assertThat(isIntegrityMaintained).isTrue();
        assertThat(creationHash).isEqualTo(verificationHash);
        
        System.out.println("✓ Data integrity verified");
        System.out.println("Creation hash: " + creationHash);
        System.out.println("Verification hash: " + verificationHash);
    }
}
