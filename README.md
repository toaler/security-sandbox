# Security Sandbox

A Java 21 Maven project demonstrating cryptographic libraries and security testing capabilities with comprehensive examples of Message Digest, MAC, and HMAC implementations.

## Project Overview

This project serves as a sandbox environment for exploring and testing various security-related Java libraries and cryptographic concepts:

- **Google Tink**: Cryptographic library for encryption/decryption and HMAC
- **Nimbus JOSE+JWT**: JWT (JSON Web Token) creation and verification
- **JUnit 5**: Latest version for unit testing
- **AssertJ**: Fluent assertion library for readable tests
- **Cryptographic Concepts**: Message Digest, MAC, and HMAC comparison

## Prerequisites

- Java 21 or higher
- Maven 3.6 or higher

## Project Structure

```
security-sandbox/
├── pom.xml                          # Maven configuration
├── README.md                        # This file
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/example/
│   │   │       └── App.java         # Main application with demos
│   │   └── resources/               # Application resources
│   └── test/
│       ├── java/
│       │   └── com/example/
│       │       └── integrity/       # Data integrity and crypto tests
│       │           ├── IntegrityTest.java           # Data integrity verification
│       │           ├── TinkHmacTest.java            # Tink HMAC demonstrations
│       │           └── CryptographicComparisonTest.java # MD, MAC, HMAC comparison
│       └── resources/
│           └── com/example/integrity/
│               └── warehouse-refunds.json           # Sample data for testing
```

## Dependencies

### Core Dependencies
- **Google Tink** (v1.12.0): Cryptographic library for encryption/decryption and HMAC operations
- **Nimbus JOSE+JWT** (v9.37): JWT creation, signing, and verification

### Test Dependencies
- **JUnit Jupiter** (v5.10.1): Latest GA version of JUnit 5 for unit testing
- **AssertJ** (v3.24.2): Fluent assertion library for readable test assertions

## Getting Started

### 1. Clone and Navigate
```bash
cd security-sandbox
```

### 2. Compile the Project
```bash
mvn compile
```

### 3. Run Tests
```bash
mvn test
```

### 4. Run the Application
```bash
mvn exec:java -Dexec.mainClass="com.example.App"
```

Or compile and run directly:
```bash
mvn compile exec:java -Dexec.mainClass="com.example.App"
```

## Features Demonstrated

### Google Tink Encryption
The main application demonstrates:
- AES-GCM encryption/decryption
- Key generation and management
- Associated authenticated encryption (AEAD)

### Nimbus JWT
The application shows:
- JWT claims set creation
- HMAC-SHA256 signing
- JWT parsing and verification

### Cryptographic Concepts Comparison
The project provides comprehensive examples of three fundamental cryptographic concepts:

#### 1. Message Digest (Hash Function)
- **Purpose**: Data integrity verification
- **Characteristics**: Deterministic, no key required
- **Implementation**: Standard Java `MessageDigest.SHA-256`
- **Use Cases**: File checksums, digital fingerprints, blockchain transactions

#### 2. MAC (Message Authentication Code)
- **Purpose**: Data integrity + authentication
- **Characteristics**: Key-based, deterministic with same key
- **Implementation**: Custom implementation using hash(key || data)
- **Use Cases**: API request signing, authenticated data transmission
- **Note**: Generic concept, not a standardized algorithm

#### 3. HMAC (Hash-based Message Authentication Code)
- **Purpose**: Data integrity + authentication + security
- **Characteristics**: Standardized, key-based, resistant to attacks
- **Implementation**: Google Tink's HMAC-SHA256 with automatic key management
- **Use Cases**: JWT tokens, secure protocols, maximum security scenarios
- **Note**: Specific standardized algorithm (RFC 2104), not just a concept

### Testing with JUnit 5 and AssertJ
The test suite demonstrates:
- Nested test classes
- Descriptive test names with `@DisplayName`
- Fluent assertions with AssertJ
- Exception testing
- Collection and string assertions
- Comprehensive cryptographic concept comparisons

## Cryptographic Concepts Comparison

### Security Hierarchy
```
Message Digest < MAC < HMAC
     (Lowest)           (Highest)
```

### Detailed Comparison Table

| Feature | Message Digest | MAC | HMAC |
|---------|---------------|-----|------|
| **Key Required** | ❌ No | ✅ Yes | ✅ Yes |
| **Authentication** | ❌ No | ✅ Yes | ✅ Yes |
| **Integrity** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Deterministic** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Standard** | ✅ Yes | ❌ No | ✅ Yes |
| **Security Level** | Medium | High | Very High |
| **Attack Resistance** | Basic | Good | Excellent |
| **Implementation** | Standard Java | Custom | Google Tink |
| **Output Length** | 64 chars | 64 chars | 74 chars |

### MAC vs HMAC: Key Differences

**MAC** is a **generic concept** for any keyed hash function, while **HMAC** is a **specific, standardized algorithm**.

#### MAC (Message Authentication Code)
- **Type**: Generic concept/approach
- **Standard**: ❌ No standardized implementation
- **Security**: Depends on implementation quality
- **Vulnerabilities**: Can be vulnerable to length extension attacks
- **Implementation**: Custom, varies by developer

#### HMAC (Hash-based Message Authentication Code)
- **Type**: Specific standardized algorithm (RFC 2104)
- **Standard**: ✅ RFC 2104 standard
- **Security**: Mathematically proven secure
- **Vulnerabilities**: Resistant to length extension attacks
- **Implementation**: Consistent across all platforms

#### MAC vs HMAC Comparison Table

| Feature | MAC | HMAC |
|---------|-----|------|
| **Type** | Generic concept | Specific algorithm |
| **Standard** | ❌ No | ✅ RFC 2104 |
| **Implementation** | Custom/variable | Standardized |
| **Security** | Depends on implementation | Proven secure |
| **Attack Resistance** | Variable | High (length extension resistant) |
| **Consistency** | ❌ No | ✅ Yes |
| **Key Handling** | Simple concatenation | Complex padding scheme |
| **Production Ready** | ❌ Usually not | ✅ Yes |

#### Security Comparison
```
MAC: hash(key || message)     // Simple concatenation
HMAC: H((key ⊕ opad) || H((key ⊕ ipad) || message))  // Complex padding scheme
```

**Bottom Line**: HMAC is always a MAC, but not all MACs are HMAC!

### When to Use Each

#### Use Message Digest when:
- ✅ You only need data integrity
- ✅ No authentication required
- ✅ Same input should always produce same output
- ✅ Example: File checksums, blockchain hashes

#### Use MAC when:
- ✅ You need both integrity AND authentication
- ✅ You have a custom authentication scheme
- ✅ You understand the security implications
- ❌ **Avoid for production systems** requiring high security
- ✅ Example: Custom API authentication

#### Use HMAC when:
- ✅ You need both integrity AND authentication
- ✅ You want maximum security
- ✅ You're following security standards
- ✅ **Recommended for production systems**
- ✅ Example: JWT tokens, API signatures, secure protocols

## Example Output

When you run the application, you'll see output similar to:

```
Security Sandbox - Java 21 Maven Project
========================================

--- Google Tink Encryption Demo ---
Encrypted data length: 28 bytes
Original: Hello, Tink!
Decrypted: Hello, Tink!
Encryption/Decryption successful: true

--- Nimbus JWT Demo ---
Generated JWT: eyJhbGciOiJIUzI1NiJ9...
JWT Subject: user123
JWT Issuer: security-sandbox
JWT Role: admin
```

### Real-World Examples

#### MAC (Generic) Example:
```java
// Custom API authentication
String apiKey = "mySecretKey";
String requestBody = "{\"user\":\"john\",\"action\":\"login\"}";
String signature = createSimpleMac(requestBody.getBytes(), apiKey.getBytes());
// Result: Custom implementation, varies by developer
```

#### HMAC (Standardized) Example:
```java
// JWT token signing (standard)
String secret = "mySecretKey";
String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
String payload = "{\"user\":\"john\",\"exp\":1234567890}";
String hmac = HMAC-SHA256(secret, header + "." + payload);
// Result: Standardized, same across all JWT implementations
```

### Cryptographic Comparison Test Output

```
=== MAC (Simple Implementation) ===
Input: Authenticated message
MAC with key1: 41b89423c1f220cb67d61ce2e2cc9c4a663ee679c49507573c8700f2341119b5
MAC with key2: 370dcb79d971822b471168faf9378599918d0f539ae203afdb545c199ff8cad1
Different keys produce different MACs: true

=== HMAC (Tink Implementation) ===
Input: HMAC authenticated message
HMAC 1: 014ac8857740dd1565e567a0a1ad87124692a2de908ac415ba36918bb9fe6c3ba9487867a0
HMAC 2: 017ba537dcfbc2d555c0485668f2bd3a68d88e83fff8ad9311b8e56f9c2c10bcb0ec2e4c47
Length: 74 characters
Different each time (random keys): true

=== Security Hierarchy Comparison ===
Input: Compare me
Message Digest: a52f0804e7d1d3ba2baee33559c90e505e332f35bc881c0e36aaac671b397c4a (64 chars)
MAC: 3dc3a6a48c31076c728f560b03b64fec9d503c9eb76794c2b5c9483fa1115828 (64 chars)
HMAC: 01633dfe3b57355e45d4f522ba4016b4bedb14e63e960893d30f48361b7daea0365707a995 (74 chars)

Security Level: Message Digest < MAC < HMAC
Features:
  Message Digest: Integrity only, no key
  MAC: Integrity + Authentication, requires key
  HMAC: Integrity + Authentication + Standardized + Secure
```

## Maven Commands

### Build
```bash
mvn clean compile
```

### Test
```bash
mvn test
```

### Package
```bash
mvn package
```

### Run with Dependencies
```bash
mvn exec:java -Dexec.mainClass="com.example.App"
```

### Run Specific Test Suites

#### Message Digest Tests
```bash
mvn test -Dtest=MessageDigestTest
```

#### MAC Tests
```bash
mvn test -Dtest=MacTest
```

#### HMAC Tests
```bash
mvn test -Dtest=HmacTest
```

#### Cryptographic Comparison Tests
```bash
mvn test -Dtest=CryptographicComparisonTest
```

#### All Integrity Tests
```bash
mvn test -Dtest="*Test"
```

## Technical Implementation Details

### Message Digest Implementation
```java
private String createMessageDigest(byte[] data) {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(data);
    return bytesToHex(hash);
}
```

### MAC Implementation
```java
private String createSimpleMac(byte[] data, byte[] key) {
    // Simple MAC: hash(key || data)
    byte[] combined = new byte[key.length + data.length];
    System.arraycopy(key, 0, combined, 0, key.length);
    System.arraycopy(data, 0, combined, key.length, data.length);
    
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] mac = digest.digest(combined);
    return bytesToHex(mac);
}
```

### HMAC Implementation (Google Tink)
```java
private String createHmac(byte[] data) {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(HmacKeyManager.hmacSha256Template());
    Mac mac = keysetHandle.getPrimitive(Mac.class);
    byte[] hmac = mac.computeMac(data);
    return bytesToHex(hmac);
}
```

### Key Differences in Practice

1. **Message Digest**: Always produces same output for same input
2. **MAC**: Produces same output for same input + key combination
3. **HMAC**: Produces different output each time (due to random key generation by Tink)

### Security Vulnerabilities

#### MAC Vulnerabilities:
```java
// Simple MAC can be vulnerable to length extension attacks
String simpleMac = hash(key + message);
// Attacker can potentially extend this without knowing the key
```

#### HMAC Security:
```java
// HMAC is resistant to length extension attacks
String hmac = HMAC(key, message);
// Even if attacker knows HMAC, they can't extend it
```

### Best Practices

- **For Production Systems**: Always use HMAC or other standardized MACs
- **Avoid Custom MACs**: Unless you have deep cryptographic expertise
- **Key Management**: Use secure key generation and storage
- **Algorithm Choice**: Prefer HMAC-SHA256 or HMAC-SHA512 for most use cases

## Summary: Choosing the Right Cryptographic Tool

### Quick Decision Guide

| Need | Use | Why |
|------|-----|-----|
| **Data Integrity Only** | Message Digest (SHA-256) | Simple, deterministic, no key needed |
| **Custom Authentication** | MAC | Key-based, but understand the risks |
| **Production Authentication** | HMAC | Standardized, secure, proven |
| **Maximum Security** | HMAC | Resistant to attacks, industry standard |

### Key Takeaways

1. **Message Digest**: For integrity verification only
2. **MAC**: Generic concept - avoid custom implementations in production
3. **HMAC**: Specific algorithm - use for all authentication needs
4. **Security Hierarchy**: Message Digest < MAC < HMAC

**Remember**: HMAC is always a MAC, but not all MACs are HMAC!

## Security Notes

⚠️ **Important**: This is a sandbox project for learning purposes. The cryptographic examples use:
- Hardcoded secrets (not suitable for production)
- Simple HMAC signing (consider RSA/ECDSA for production)
- In-memory key generation (use proper key management in production)

For production use, always:
- Use secure key management systems
- Generate cryptographically secure random keys
- Follow security best practices
- Consider using hardware security modules (HSMs)
- **Prefer HMAC over custom MAC implementations**

## Contributing

Feel free to extend this sandbox with additional security libraries and examples. Some ideas:
- Bouncy Castle cryptography
- Spring Security integration
- OAuth2/OIDC examples
- Certificate handling
- Secure random number generation
- Additional hash functions (SHA-512, SHA-3)
- Digital signature implementations
- Key derivation functions (PBKDF2, Argon2)
- Symmetric encryption examples
- Asymmetric encryption examples

## License

This project is for educational purposes. Use at your own risk.
