package com.example.integrity;

import com.example.CryptoUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.assertj.core.api.Assertions.*;

import java.security.SecureRandom;
import java.util.Optional;

/**
 * Test class demonstrating JSON Web Structure (JWS) functionality.
 * JWS provides a way to digitally sign and verify JSON content with proper structure.
 */
@DisplayName("JSON Web Structure (JWS) Tests")
class JwsTest {

    private byte[] secretKey;
    private byte[] wrongKey;
    private SecureRandom secureRandom;

    @BeforeEach
    void setUp() {
        // Generate a secure random key for HMAC-SHA256
        secureRandom = new SecureRandom();
        secretKey = new byte[32]; // 256 bits for HMAC-SHA256
        secureRandom.nextBytes(secretKey);
        
        // Generate a different key for testing verification failures
        wrongKey = new byte[32];
        secureRandom.nextBytes(wrongKey);
    }

    @Test
    @DisplayName("Should successfully sign content with HMAC-SHA256")
    void shouldSuccessfullySignContentWithHmacSha256() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        
        // When
        String jwsToken = CryptoUtils.signJwsHmacSha256(content, secretKey);
        
        // Then
        assertThat(jwsToken).isNotNull().isNotEmpty();
        assertThat(CryptoUtils.isValidJwsFormat(jwsToken)).isTrue();
        
        System.out.println("=== JWS Structure Success ===");
        System.out.println("Original content: " + content);
        System.out.println("JWS Token: " + jwsToken);
        System.out.println("Token format valid: " + CryptoUtils.isValidJwsFormat(jwsToken));
        
        // Verify the token structure (header.payload.signature)
        String[] parts = jwsToken.split("\\.");
        assertThat(parts).hasSize(3);
        System.out.println("Token structure parts:");
        System.out.println("  Header: " + parts[0]);
        System.out.println("  Payload: " + parts[1]);
        System.out.println("  Signature: " + parts[2]);
    }

    @Test
    @DisplayName("Should successfully verify a valid JWS token")
    void shouldSuccessfullyVerifyValidJwsToken() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jwsToken = CryptoUtils.signJwsHmacSha256(content, secretKey);
        
        // When
        Optional<String> verifiedPayload = CryptoUtils.verifyJwsHmacSha256(jwsToken, secretKey);
        
        // Then
        assertThat(verifiedPayload).isPresent();
        assertThat(verifiedPayload.get()).isEqualTo(content);
        
        System.out.println("=== JWS Verification Success ===");
        System.out.println("Original content: " + content);
        System.out.println("JWS Token: " + jwsToken);
        System.out.println("Verified payload: " + verifiedPayload.get());
        System.out.println("Verification successful: " + verifiedPayload.isPresent());
    }

    @Test
    @DisplayName("Should fail verification with wrong key")
    void shouldFailVerificationWithWrongKey() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jwsToken = CryptoUtils.signJwsHmacSha256(content, secretKey);
        
        // When
        Optional<String> verifiedPayload = CryptoUtils.verifyJwsHmacSha256(jwsToken, wrongKey);
        
        // Then
        assertThat(verifiedPayload).isEmpty();
        
        System.out.println("=== JWS Verification Failure ===");
        System.out.println("Original content: " + content);
        System.out.println("JWS Token: " + jwsToken);
        System.out.println("Verification with wrong key: " + verifiedPayload.isPresent());
        System.out.println("Expected: false (verification should fail)");
        System.out.println("This demonstrates the security of JWS - only the correct key can verify the signature");
    }

    @Test
    @DisplayName("Should extract payload without verification")
    void shouldExtractPayloadWithoutVerification() {
        // Given
        String content = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jwsToken = CryptoUtils.signJwsHmacSha256(content, secretKey);
        
        // When
        Optional<String> extractedPayload = CryptoUtils.extractJwsPayload(jwsToken);
        
        // Then
        assertThat(extractedPayload).isPresent();
        assertThat(extractedPayload.get()).isEqualTo(content);
        
        System.out.println("=== JWS Payload Extraction ===");
        System.out.println("Original content: " + content);
        System.out.println("JWS Token: " + jwsToken);
        System.out.println("Extracted payload: " + extractedPayload.get());
        System.out.println("Note: Payload extraction works regardless of signature validity");
        System.out.println("This is useful for debugging or when you need to read the content without verification");
    }

    @Test
    @DisplayName("Should handle different content types")
    void shouldHandleDifferentContentTypes() {
        // Given
        String[] testContents = {
            "Simple text",
            "Text with special characters: !@#$%^&*()",
            "Unicode content: 🚀🔐✨",
            "JSON content: {\"key\": \"value\", \"number\": 42}",
            "Long content: " + "A".repeat(1000)
        };
        
        System.out.println("=== JWS Content Type Handling ===");
        
        for (String content : testContents) {
            // When
            String jwsToken = CryptoUtils.signJwsHmacSha256(content, secretKey);
            Optional<String> verifiedPayload = CryptoUtils.verifyJwsHmacSha256(jwsToken, secretKey);
            
            // Then
            assertThat(verifiedPayload).isPresent();
            assertThat(verifiedPayload.get()).isEqualTo(content);
            
            System.out.println("Content type: " + content.getClass().getSimpleName());
            System.out.println("  Length: " + content.length() + " characters");
            System.out.println("  JWS Token length: " + jwsToken.length() + " characters");
            System.out.println("  Verification: " + (verifiedPayload.isPresent() ? "SUCCESS" : "FAILED"));
            System.out.println("  Sample: " + (content.length() > 50 ? content.substring(0, 50) + "..." : content));
            System.out.println();
        }
    }

    @Test
    @DisplayName("Should demonstrate JWS security properties")
    void shouldDemonstrateJwsSecurityProperties() {
        // Given
        String originalContent = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String jwsToken = CryptoUtils.signJwsHmacSha256(originalContent, secretKey);
        
        System.out.println("=== JWS Security Properties ===");
        System.out.println("Original content: " + originalContent);
        System.out.println("JWS Token: " + jwsToken);
        
        // Test 1: Verification with correct key
        Optional<String> correctVerification = CryptoUtils.verifyJwsHmacSha256(jwsToken, secretKey);
        assertThat(correctVerification).isPresent();
        System.out.println("1. Correct key verification: " + (correctVerification.isPresent() ? "SUCCESS" : "FAILED"));
        
        // Test 2: Verification with wrong key
        Optional<String> wrongKeyVerification = CryptoUtils.verifyJwsHmacSha256(jwsToken, wrongKey);
        assertThat(wrongKeyVerification).isEmpty();
        System.out.println("2. Wrong key verification: " + (wrongKeyVerification.isPresent() ? "SUCCESS" : "FAILED"));
        
        // Test 3: Tampered token (modify the payload part)
        String[] parts = jwsToken.split("\\.");
        String tamperedToken = parts[0] + "." + 
                              java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("TAMPERED".getBytes()) + "." + 
                              parts[2];
        
        Optional<String> tamperedVerification = CryptoUtils.verifyJwsHmacSha256(tamperedToken, secretKey);
        assertThat(tamperedVerification).isEmpty();
        System.out.println("3. Tampered token verification: " + (tamperedVerification.isPresent() ? "SUCCESS" : "FAILED"));
        
        // Test 4: Malformed token
        String malformedToken = "not.a.valid.jws.token";
        Optional<String> malformedVerification = CryptoUtils.verifyJwsHmacSha256(malformedToken, secretKey);
        assertThat(malformedVerification).isEmpty();
        System.out.println("4. Malformed token verification: " + (malformedVerification.isPresent() ? "SUCCESS" : "FAILED"));
        
        System.out.println();
        System.out.println("=== Security Summary ===");
        System.out.println("✓ JWS provides integrity: Content cannot be modified without detection");
        System.out.println("✓ JWS provides authenticity: Only holders of the secret key can create valid signatures");
        System.out.println("✓ JWS provides non-repudiation: Signers cannot deny creating the signature");
        System.out.println("✓ JWS is tamper-evident: Any modification breaks verification");
    }

    @Test
    @DisplayName("Should demonstrate JWS use cases with verification")
    void shouldDemonstrateJwsUseCases() {
        System.out.println("=== JWS Use Cases with Verification ===");
        
        // Use Case 1: Order Data Integrity
        String orderData = "{\n  \"orders\": [\n    {\n      \"orderId\": \"12345\",\n      \"amount\": 500\n    },\n    {\n      \"orderId\": \"56789\",\n      \"amount\": 250\n    }\n  ]\n}";
        String orderToken = CryptoUtils.signJwsHmacSha256(orderData, secretKey);
        System.out.println("1. Order Data Integrity:");
        System.out.println("   Order data: " + orderData);
        System.out.println("   JWS Token: " + orderToken);
        System.out.println("   Purpose: Ensure order data hasn't been modified in transit");
        
        // Verify the order data JWS token
        Optional<String> verifiedOrderData = CryptoUtils.verifyJwsHmacSha256(orderToken, secretKey);
        assertThat(verifiedOrderData).isPresent();
        assertThat(verifiedOrderData.get()).isEqualTo(orderData);
        System.out.println("   ✓ Verification: SUCCESS - Payload matches expected order data");
        
        // Use Case 2: API Request Authentication
        String apiRequest = "{\"method\": \"POST\", \"path\": \"/api/orders\", \"timestamp\": \"2024-01-01T00:00:00Z\", \"orderData\": " + orderData + "}";
        String apiToken = CryptoUtils.signJwsHmacSha256(apiRequest, secretKey);
        System.out.println();
        System.out.println("2. API Request Authentication:");
        System.out.println("   Request: " + apiRequest);
        System.out.println("   JWS Token: " + apiToken);
        System.out.println("   Purpose: Verify request authenticity and integrity");
        
        // Verify the API request JWS token
        Optional<String> verifiedApiRequest = CryptoUtils.verifyJwsHmacSha256(apiToken, secretKey);
        assertThat(verifiedApiRequest).isPresent();
        assertThat(verifiedApiRequest.get()).isEqualTo(apiRequest);
        System.out.println("   ✓ Verification: SUCCESS - Payload matches expected API request");
        
        // Use Case 3: Financial Transaction Security
        String transactionData = "{\"orderId\": \"12345\", \"amount\": 500, \"currency\": \"USD\", \"timestamp\": \"2024-01-01T00:00:00Z\"}";
        String transactionToken = CryptoUtils.signJwsHmacSha256(transactionData, secretKey);
        System.out.println();
        System.out.println("3. Financial Transaction Security:");
        System.out.println("   Transaction data: " + transactionData);
        System.out.println("   JWS Token: " + transactionToken);
        System.out.println("   Purpose: Secure financial transactions with tamper detection");
        
        // Verify the transaction JWS token
        Optional<String> verifiedTransaction = CryptoUtils.verifyJwsHmacSha256(transactionToken, secretKey);
        assertThat(verifiedTransaction).isPresent();
        assertThat(verifiedTransaction.get()).isEqualTo(transactionData);
        System.out.println("   ✓ Verification: SUCCESS - Payload matches expected transaction data");
        
        // Use Case 4: Order Processing Workflow
        String workflowData = "{\"step\": \"order_confirmation\", \"orderId\": \"12345\", \"status\": \"confirmed\", \"timestamp\": \"2024-01-01T00:00:00Z\"}";
        String workflowToken = CryptoUtils.signJwsHmacSha256(workflowData, secretKey);
        System.out.println();
        System.out.println("4. Order Processing Workflow:");
        System.out.println("   Workflow data: " + workflowData);
        System.out.println("   JWS Token: " + workflowToken);
        System.out.println("   Purpose: Verify workflow step authenticity and prevent replay attacks");
        
        // Verify the workflow JWS token
        Optional<String> verifiedWorkflow = CryptoUtils.verifyJwsHmacSha256(workflowToken, secretKey);
        assertThat(verifiedWorkflow).isPresent();
        assertThat(verifiedWorkflow.get()).isEqualTo(workflowData);
        System.out.println("   ✓ Verification: SUCCESS - Payload matches expected workflow data");
        
        // Additional verification: Test that wrong keys fail for all use cases
        System.out.println();
        System.out.println("=== Security Verification ===");
        System.out.println("Testing that wrong keys fail verification for all use cases:");
        
        Optional<String> wrongKeyOrder = CryptoUtils.verifyJwsHmacSha256(orderToken, wrongKey);
        Optional<String> wrongKeyApi = CryptoUtils.verifyJwsHmacSha256(apiToken, wrongKey);
        Optional<String> wrongKeyTransaction = CryptoUtils.verifyJwsHmacSha256(transactionToken, wrongKey);
        Optional<String> wrongKeyWorkflow = CryptoUtils.verifyJwsHmacSha256(workflowToken, wrongKey);
        
        assertThat(wrongKeyOrder).isEmpty();
        assertThat(wrongKeyApi).isEmpty();
        assertThat(wrongKeyTransaction).isEmpty();
        assertThat(wrongKeyWorkflow).isEmpty();
        
        System.out.println("   ✓ Wrong key verification fails for order data: " + wrongKeyOrder.isPresent());
        System.out.println("   ✓ Wrong key verification fails for API request: " + wrongKeyApi.isPresent());
        System.out.println("   ✓ Wrong key verification fails for transaction: " + wrongKeyTransaction.isPresent());
        System.out.println("   ✓ Wrong key verification fails for workflow: " + wrongKeyWorkflow.isPresent());
        
        System.out.println();
        System.out.println("=== JWS Structure Benefits ===");
        System.out.println("• Structured: Three-part format (header.payload.signature)");
        System.out.println("• Compact: Base64-encoded format is URL-safe and compact");
        System.out.println("• Standard: RFC 7515 standard, widely supported");
        System.out.println("• Flexible: Can use different algorithms (HMAC, RSA, ECDSA)");
        System.out.println("• Secure: Provides integrity, authenticity, and non-repudiation");
        System.out.println("• Verifiable: All signed content can be verified to match original data");
    }
} 