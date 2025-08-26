package com.example.integrity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Test class demonstrating generic MAC (Message Authentication Code) functionality.
 * This shows a simple MAC implementation using hash(key || message).
 */
@DisplayName("MAC Tests")
class MacTest {

    /**
     * Creates a simple MAC using hash(key || message) approach.
     * This is a basic implementation for educational purposes.
     */
    private String createSimpleMac(byte[] data, byte[] key) {
        try {
            // Simple MAC: hash(key || message)
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
    @DisplayName("Should create MAC with key and message")
    void shouldCreateMacWithKeyAndMessage() {
        // Given
        String message = "Authenticated message";
        String key = "mySecretKey";
        byte[] messageBytes = message.getBytes();
        byte[] keyBytes = key.getBytes();
        
        // When
        String mac = createSimpleMac(messageBytes, keyBytes);
        
        // Then
        assertThat(mac).isNotNull().hasSize(64);
        assertThat(mac).matches("^[a-f0-9]{64}$");
        
        System.out.println("MAC created: " + mac);
        System.out.println("Key: " + key);
        System.out.println("Message: " + message);
    }

    @Test
    @DisplayName("Should produce different MACs with different keys")
    void shouldProduceDifferentMacsWithDifferentKeys() {
        // Given
        String message = "Same message, different keys";
        byte[] messageBytes = message.getBytes();
        byte[] key1Bytes = "key1".getBytes();
        byte[] key2Bytes = "key2".getBytes();
        
        // When
        String mac1 = createSimpleMac(messageBytes, key1Bytes);
        String mac2 = createSimpleMac(messageBytes, key2Bytes);
        
        // Then
        assertThat(mac1).isNotEqualTo(mac2);
        assertThat(mac1).hasSize(64);
        assertThat(mac2).hasSize(64);
        
        System.out.println("MAC with key1: " + mac1);
        System.out.println("MAC with key2: " + mac2);
        System.out.println("Different keys produce different MACs: " + !mac1.equals(mac2));
    }

    @Test
    @DisplayName("Should produce same MAC with same key and message")
    void shouldProduceSameMacWithSameKeyAndMessage() {
        // Given
        String message = "Consistent message";
        String key = "consistentKey";
        byte[] messageBytes = message.getBytes();
        byte[] keyBytes = key.getBytes();
        
        // When
        String mac1 = createSimpleMac(messageBytes, keyBytes);
        String mac2 = createSimpleMac(messageBytes, keyBytes);
        
        // Then
        assertThat(mac1).isEqualTo(mac2);
        assertThat(mac1).hasSize(64);
        
        System.out.println("MAC 1: " + mac1);
        System.out.println("MAC 2: " + mac2);
        System.out.println("Same key produces same MAC: " + mac1.equals(mac2));
    }

    @Test
    @DisplayName("Should detect message tampering through MAC verification")
    void shouldDetectMessageTamperingThroughMacVerification() {
        // Given
        String originalMessage = "Original message";
        String tamperedMessage = "Original message!";
        String key = "verificationKey";
        byte[] originalBytes = originalMessage.getBytes();
        byte[] tamperedBytes = tamperedMessage.getBytes();
        byte[] keyBytes = key.getBytes();
        
        // When
        String originalMac = createSimpleMac(originalBytes, keyBytes);
        String tamperedMac = createSimpleMac(tamperedBytes, keyBytes);
        
        // Then
        assertThat(originalMac).isNotEqualTo(tamperedMac);
        assertThat(originalMac).hasSize(64);
        assertThat(tamperedMac).hasSize(64);
        
        System.out.println("Original message: " + originalMessage);
        System.out.println("Original MAC: " + originalMac);
        System.out.println("Tampered message: " + tamperedMessage);
        System.out.println("Tampered MAC: " + tamperedMac);
        System.out.println("Tampering detected: " + !originalMac.equals(tamperedMac));
    }

    @Test
    @DisplayName("Should demonstrate MAC vs Message Digest differences")
    void shouldDemonstrateMacVsMessageDigestDifferences() {
        // Given
        String message = "Compare MAC vs Message Digest";
        String key = "macKey";
        byte[] messageBytes = message.getBytes();
        byte[] keyBytes = key.getBytes();
        
        // When - Create MAC
        String mac = createSimpleMac(messageBytes, keyBytes);
        
        // And - Create Message Digest (no key)
        String messageDigest;
        try {
            messageDigest = bytesToHex(MessageDigest.getInstance("SHA-256").digest(messageBytes));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
        
        // Then
        assertThat(mac).isNotEqualTo(messageDigest);
        assertThat(mac).hasSize(64);
        assertThat(messageDigest).hasSize(64);
        
        System.out.println("=== MAC vs Message Digest Comparison ===");
        System.out.println("Message: " + message);
        System.out.println("Key: " + key);
        System.out.println("MAC (with key): " + mac);
        System.out.println("Message Digest (no key): " + messageDigest);
        System.out.println("Different: " + !mac.equals(messageDigest));
        System.out.println();
        System.out.println("Key differences:");
        System.out.println("- MAC requires a secret key");
        System.out.println("- Message Digest is deterministic without key");
        System.out.println("- MAC provides authentication + integrity");
        System.out.println("- Message Digest provides integrity only");
    }

    @Test
    @DisplayName("Should show MAC vulnerabilities compared to HMAC")
    void shouldShowMacVulnerabilitiesComparedToHmac() {
        // Given
        String message = "Vulnerable message";
        String key = "secret";
        byte[] messageBytes = message.getBytes();
        byte[] keyBytes = key.getBytes();
        
        // When
        String mac = createSimpleMac(messageBytes, keyBytes);
        
        // Then
        assertThat(mac).isNotNull().hasSize(64);
        
        System.out.println("=== MAC Security Considerations ===");
        System.out.println("MAC implementation: hash(key || message)");
        System.out.println("MAC result: " + mac);
        System.out.println();
        System.out.println("⚠️  Security Vulnerabilities:");
        System.out.println("- Length extension attacks possible");
        System.out.println("- No standardized padding scheme");
        System.out.println("- Implementation-dependent security");
        System.out.println("- Not cryptographically proven secure");
        System.out.println();
        System.out.println("✅ HMAC Advantages:");
        System.out.println("- Resistant to length extension attacks");
        System.out.println("- Standardized algorithm (RFC 2104)");
        System.out.println("- Cryptographically proven secure");
        System.out.println("- Consistent across implementations");
    }

    @Test
    @DisplayName("Should demonstrate MAC use cases")
    void shouldDemonstrateMacUseCases() {
        // Given
        String apiRequest = "POST /api/users HTTP/1.1\nContent-Type: application/json\n{\"name\":\"John\"}";
        String apiKey = "api_secret_key_123";
        byte[] requestBytes = apiRequest.getBytes();
        byte[] keyBytes = apiKey.getBytes();
        
        // When
        String signature = createSimpleMac(requestBytes, keyBytes);
        
        // Then
        assertThat(signature).isNotNull().hasSize(64);
        
        System.out.println("=== MAC Use Cases ===");
        System.out.println("Example: API Request Authentication");
        System.out.println("Request: " + apiRequest.replace("\n", "\\n"));
        System.out.println("API Key: " + apiKey);
        System.out.println("Signature: " + signature);
        System.out.println();
        System.out.println("Common MAC Use Cases:");
        System.out.println("✓ API request signing");
        System.out.println("✓ Authenticated data transmission");
        System.out.println("✓ Custom authentication schemes");
        System.out.println("✓ Simple integrity verification");
        System.out.println();
        System.out.println("⚠️  Note: For production systems, prefer HMAC over custom MAC implementations");
    }
}
