package com.example.integrity;

import com.example.CryptoUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.assertj.core.api.Assertions.*;

import java.security.SecureRandom;

/**
 * Test class demonstrating JSON Web Encryption (JWE) functionality.
 * JWE provides integrity, authentication, and confidentiality when used in direct encryption mode.
 */
@DisplayName("JSON Web Encryption (JWE) Tests")
class JweTest {

    private byte[] aesKey;
    private byte[] wrongKey;
    private SecureRandom secureRandom;

    @BeforeEach
    void setUp() {
        // Generate a secure random AES-256 key
        secureRandom = new SecureRandom();
        aesKey = new byte[32]; // 256 bits for AES-256
        secureRandom.nextBytes(aesKey);
        
        // Generate a different key for testing decryption failures
        wrongKey = new byte[32];
        secureRandom.nextBytes(wrongKey);
    }

    @Test
    @DisplayName("Should successfully encrypt content as JWE")
    void shouldSuccessfullyEncryptContentAsJwe() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        
        // When
        String jweToken = CryptoUtils.encryptAsJwe(content, aesKey);
        
        // Then
        assertThat(jweToken).isNotNull().isNotEmpty();
        assertThat(CryptoUtils.isValidJweFormat(jweToken)).isTrue();
        
        System.out.println("=== JWE Encryption Success ===");
        System.out.println("Original content: " + content);
        System.out.println("JWE Token: " + jweToken);
        System.out.println("Token format valid: " + CryptoUtils.isValidJweFormat(jweToken));
        
        // Verify the JWE structure (header.encrypted_key.iv.ciphertext.tag)
        String[] parts = jweToken.split("\\.");
        assertThat(parts).hasSize(5);
        System.out.println("JWE structure parts:");
        System.out.println("  Header: " + parts[0]);
        System.out.println("  Encrypted Key: " + parts[1]);
        System.out.println("  IV: " + parts[2]);
        System.out.println("  Ciphertext: " + parts[3]);
        System.out.println("  Authentication Tag: " + parts[4]);
    }

    @Test
    @DisplayName("Should successfully decrypt a valid JWE token")
    void shouldSuccessfullyDecryptValidJweToken() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jweToken = CryptoUtils.encryptAsJwe(content, aesKey);
        
        // When
        String decryptedContent = CryptoUtils.decryptJwe(jweToken, aesKey);
        
        // Then
        assertThat(decryptedContent).isNotNull().isEqualTo(content);
        
        System.out.println("=== JWE Decryption Success ===");
        System.out.println("Original content: " + content);
        System.out.println("JWE Token: " + jweToken);
        System.out.println("Decrypted content: " + decryptedContent);
        System.out.println("Decryption successful: " + content.equals(decryptedContent));
    }

    @Test
    @DisplayName("Should fail decryption with wrong key")
    void shouldFailDecryptionWithWrongKey() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jweToken = CryptoUtils.encryptAsJwe(content, aesKey);
        
        // When & Then
        assertThatThrownBy(() -> CryptoUtils.decryptJwe(jweToken, wrongKey))
            .isInstanceOf(RuntimeException.class);
        
        System.out.println("=== JWE Decryption Failure ===");
        System.out.println("Original content: " + content);
        System.out.println("JWE Token: " + jweToken);
        System.out.println("Decryption with wrong key: FAILED (as expected)");
        System.out.println("This demonstrates JWE's confidentiality - only the correct key can decrypt the content");
    }

    @Test
    @DisplayName("Should extract JWE header without decryption")
    void shouldExtractJweHeaderWithoutDecryption() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jweToken = CryptoUtils.encryptAsJwe(content, aesKey);
        
        // When
        var header = CryptoUtils.extractJweHeader(jweToken);
        
        // Then
        assertThat(header).isPresent();
        assertThat(header.get()).contains("A256GCM");
        assertThat(header.get()).contains("dir");
        
        System.out.println("=== JWE Header Extraction ===");
        System.out.println("JWE Token: " + jweToken);
        System.out.println("Extracted header: " + header.get());
        System.out.println("Header contains encryption method: " + header.get().contains("A256GCM"));
        System.out.println("Header contains algorithm: " + header.get().contains("dir"));
        System.out.println("Note: Header extraction works without decryption, showing JWE structure");
    }

    @Test
    @DisplayName("Should demonstrate JWE cryptographic goals")
    void shouldDemonstrateJweCryptographicGoals() {
        // Given
        String originalContent = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jweToken = CryptoUtils.encryptAsJwe(originalContent, aesKey);
        
        System.out.println("=== JWE Cryptographic Goals Demonstration ===");
        System.out.println("Original content: " + originalContent);
        System.out.println("JWE Token: " + jweToken);
        
        // Test 1: Confidentiality - Content is encrypted and not readable
        System.out.println();
        System.out.println("1. CONFIDENTIALITY ✓");
        System.out.println("   - Content is encrypted and not readable in plain text");
        System.out.println("   - Only holders of the correct key can decrypt");
        System.out.println("   - Wrong keys fail decryption (demonstrated in previous test)");
        
        // Test 2: Integrity - Tampered tokens fail decryption
        String[] parts = jweToken.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + "." + parts[2] + "." + 
                              "TAMPERED_CIPHERTEXT" + "." + parts[4];
        
        assertThatThrownBy(() -> CryptoUtils.decryptJwe(tamperedToken, aesKey))
            .isInstanceOf(RuntimeException.class);
        
        System.out.println();
        System.out.println("2. INTEGRITY ✓");
        System.out.println("   - Tampered ciphertext fails decryption");
        System.out.println("   - Authentication tag ensures data hasn't been modified");
        System.out.println("   - Any change to encrypted content breaks decryption");
        
        // Test 3: Authentication - Only correct key can decrypt
        String decryptedContent = CryptoUtils.decryptJwe(jweToken, aesKey);
        assertThat(decryptedContent).isEqualTo(originalContent);
        
        System.out.println();
        System.out.println("3. AUTHENTICATION ✓");
        System.out.println("   - Only the correct key can successfully decrypt");
        System.out.println("   - Wrong keys fail decryption");
        System.out.println("   - Proves the content came from someone with the correct key");
        
        // Test 4: Non-repudiation - Not provided by JWE in direct mode
        System.out.println();
        System.out.println("4. NON-REPUDIATION ❌");
        System.out.println("   - JWE in direct mode does NOT provide non-repudiation");
        System.out.println("   - Anyone with the key can create valid JWEs");
        System.out.println("   - Cannot prove who originally encrypted the content");
        
        System.out.println();
        System.out.println("=== Cryptographic Goals Summary ===");
        System.out.println("✓ CONFIDENTIALITY: Content is encrypted and unreadable without the key");
        System.out.println("✓ INTEGRITY: Any modification to encrypted content breaks decryption");
        System.out.println("✓ AUTHENTICATION: Only holders of the correct key can decrypt");
        System.out.println("❌ NON-REPUDIATION: Cannot prove who originally encrypted the content");
        System.out.println();
        System.out.println("JWE provides 3 out of 4 cryptographic goals, making it suitable for:");
        System.out.println("  - Secure data transmission");
        System.out.println("  - Encrypted storage");
        System.out.println("  - Confidential communication");
        System.out.println("  - Data integrity protection");
    }

    @Test
    @DisplayName("Should handle different content types with JWE")
    void shouldHandleDifferentContentTypesWithJwe() {
        // Given
        String[] testContents = {
            "Simple text",
            "Text with special characters: !@#$%^&*()",
            "Unicode content: 🚀🔐✨",
            "JSON content: {\"key\": \"value\", \"number\": 42}",
            "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}"
        };
        
        System.out.println("=== JWE Content Type Handling ===");
        
        for (String content : testContents) {
            // When
            String jweToken = CryptoUtils.encryptAsJwe(content, aesKey);
            String decryptedContent = CryptoUtils.decryptJwe(jweToken, aesKey);
            
            // Then
            assertThat(decryptedContent).isEqualTo(content);
            
            System.out.println("Content type: " + content.getClass().getSimpleName());
            System.out.println("  Length: " + content.length() + " characters");
            System.out.println("  JWE Token length: " + jweToken.length() + " characters");
            System.out.println("  Encryption/Decryption: SUCCESS");
            System.out.println("  Sample: " + (content.length() > 50 ? content.substring(0, 50) + "..." : content));
            System.out.println();
        }
    }

    @Test
    @DisplayName("Should demonstrate JWE use cases")
    void shouldDemonstrateJweUseCases() {
        System.out.println("=== JWE Use Cases ===");
        
        // Use Case 1: Encrypted Order Data Storage
        String orderData = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String encryptedOrderData = CryptoUtils.encryptAsJwe(orderData, aesKey);
        System.out.println("1. Encrypted Order Data Storage:");
        System.out.println("   Order data: " + orderData);
        System.out.println("   Encrypted JWE: " + encryptedOrderData);
        System.out.println("   Purpose: Secure storage of sensitive order information");
        
        // Verify encryption/decryption works
        String decryptedOrderData = CryptoUtils.decryptJwe(encryptedOrderData, aesKey);
        assertThat(decryptedOrderData).isEqualTo(orderData);
        System.out.println("   ✓ Verification: SUCCESS - Decrypted data matches original");
        
        // Use Case 2: Secure API Communication
        String apiPayload = "{\"method\": \"POST\", \"path\": \"/api/orders\", \"timestamp\": \"2024-01-01T00:00:00Z\", \"data\": " + orderData + "}";
        String encryptedApiPayload = CryptoUtils.encryptAsJwe(apiPayload, aesKey);
        System.out.println();
        System.out.println("2. Secure API Communication:");
        System.out.println("   API payload: " + apiPayload);
        System.out.println("   Encrypted JWE: " + encryptedApiPayload);
        System.out.println("   Purpose: Secure transmission of API data");
        
        // Verify encryption/decryption works
        String decryptedApiPayload = CryptoUtils.decryptJwe(encryptedApiPayload, aesKey);
        assertThat(decryptedApiPayload).isEqualTo(apiPayload);
        System.out.println("   ✓ Verification: SUCCESS - Decrypted payload matches original");
        
        // Use Case 3: Encrypted Configuration Files
        String configData = "{\"database\": {\"host\": \"localhost\", \"port\": 5432}, \"redis\": {\"host\": \"localhost\", \"port\": 6379}}";
        String encryptedConfig = CryptoUtils.encryptAsJwe(configData, aesKey);
        System.out.println();
        System.out.println("3. Encrypted Configuration Files:");
        System.out.println("   Config data: " + configData);
        System.out.println("   Encrypted JWE: " + encryptedConfig);
        System.out.println("   Purpose: Secure storage of configuration information");
        
        // Verify encryption/decryption works
        String decryptedConfig = CryptoUtils.decryptJwe(encryptedConfig, aesKey);
        assertThat(decryptedConfig).isEqualTo(configData);
        System.out.println("   ✓ Verification: SUCCESS - Decrypted config matches original");
        
        // Use Case 4: Secure Message Exchange
        String messageData = "{\"sender\": \"alice\", \"recipient\": \"bob\", \"message\": \"Hello, this is a secret message!\", \"timestamp\": \"2024-01-01T00:00:00Z\"}";
        String encryptedMessage = CryptoUtils.encryptAsJwe(messageData, aesKey);
        System.out.println();
        System.out.println("4. Secure Message Exchange:");
        System.out.println("   Message data: " + messageData);
        System.out.println("   Encrypted JWE: " + encryptedMessage);
        System.out.println("   Purpose: Confidential communication between parties");
        
        // Verify encryption/decryption works
        String decryptedMessage = CryptoUtils.decryptJwe(encryptedMessage, aesKey);
        assertThat(decryptedMessage).isEqualTo(messageData);
        System.out.println("   ✓ Verification: SUCCESS - Decrypted message matches original");
        
        System.out.println();
        System.out.println("=== JWE Benefits ===");
        System.out.println("• Confidentiality: Content is encrypted and unreadable without the key");
        System.out.println("• Integrity: Any modification breaks decryption");
        System.out.println("• Authentication: Only correct key holders can decrypt");
        System.out.println("• Standard: RFC 7516 compliant");
        System.out.println("• Compact: Base64-encoded format is URL-safe");
        System.out.println("• Secure: Uses AES-GCM for authenticated encryption");
    }
} 