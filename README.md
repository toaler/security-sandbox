# Security Sandbox

A Java 21 Maven project demonstrating cryptographic libraries and security testing capabilities with comprehensive examples of Message Digest, MAC, and HMAC implementations.

## Project Overview

This project serves as a sandbox environment for exploring and testing various security-related Java libraries and cryptographic concepts:

- **Google Tink**: Cryptographic library for encryption/decryption and HMAC
- **Nimbus JOSE+JWT**: JWT (JSON Web Token) creation and verification
- **JOSE Standards**: JSON Web Structure (JWS) for digital signatures and authentication
- **JOSE Standards**: JSON Web Encryption (JWE) for encrypted content and confidentiality
- **JUnit 5**: Latest version for unit testing
- **AssertJ**: Fluent assertion library for readable tests
- **Cryptographic Concepts**: Message Digest, MAC, HMAC, JWS, and JWE comparison

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
│   │   │       ├── App.java         # Main application with demos
│   │   │       └── CryptoUtils.java # JWS signing and verification utilities
│   │   └── resources/               # Application resources
│   └── test/
│       ├── java/
│       │   └── com/example/
│       │       └── integrity/       # Data integrity and crypto tests
│       │           ├── IntegrityTest.java           # Data integrity verification
│       │           ├── TinkHmacTest.java            # Tink HMAC demonstrations
│       │           ├── CryptographicComparisonTest.java # MD, MAC, HMAC comparison
│       │           ├── JwsTest.java                 # JWS functionality tests
│       │           └── JweTest.java                 # JWE functionality tests
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

## JOSE (JavaScript Object Signing and Encryption)

The project now includes comprehensive support for JavaScript Object Signing and Encryption (JOSE) standards, providing secure ways to handle JSON-based security tokens and encrypted data.

### JSON Web Structure (JWS)

JSON Web Structure (JWS) provides a means of representing content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based data structures.

#### JWS Implementation Features

- **HMAC-SHA256 Algorithm**: Uses HMAC-SHA256 for signing and verification
- **RFC 7515 Compliance**: Follows JSON Web Signature standard
- **Three-Part Structure**: Implements header.payload.signature format
- **Payload Verification**: Ensures data integrity and authenticity
- **Tamper Detection**: Automatically detects any modifications to signed content

#### JWS Use Cases Demonstrated

1. **Order Data Integrity**
   - Signs order data with proper JSON structure
   - Ensures order amounts and IDs cannot be modified
   - Provides proof of data authenticity

2. **API Request Authentication**
   - Signs complete API requests including order data
   - Verifies request authenticity and integrity
   - Prevents request tampering and replay attacks

3. **Financial Transaction Security**
   - Secures financial transaction data
   - Provides tamper detection for monetary amounts
   - Ensures transaction authenticity

4. **Order Processing Workflow**
   - Signs workflow step data
   - Prevents workflow manipulation
   - Ensures process integrity

#### JWS Security Properties

| Security Property | Description | Implementation |
|-------------------|-------------|----------------|
| **Integrity** | Content cannot be modified without detection | HMAC-SHA256 signature verification |
| **Authenticity** | Only holders of the secret key can create valid signatures | Secret key-based signing |
| **Non-repudiation** | Signers cannot deny creating the signature | Cryptographic proof of origin |
| **Tamper Evidence** | Any modification breaks verification | Automatic signature validation |

#### JWS Token Structure

```
eyJhbGciOiJIUzI1NiJ9.eyJvcmRlcnMiOlt7Im9yZGVySWQiOiIxMjM0NSIsImFtb3VudCI6NTAwfSx7Im9yZGVySWQiOiI1Njc4OSIsImFtb3VudCI6MjUwfV19.signature
```

**Components:**
- **Header**: Algorithm specification (`HS256`)
- **Payload**: Base64-encoded JSON content
- **Signature**: HMAC-SHA256 signature of header.payload

#### JWS Implementation Example

```java
// Sign order data
String orderData = "{\"orders\":[{\"orderId\":\"12345\",\"amount\":500}]}";
String jwsToken = CryptoUtils.signJwsHmacSha256(orderData, secretKey);

// Verify the signature
Optional<String> verifiedData = CryptoUtils.verifyJwsHmacSha256(jwsToken, secretKey);
if (verifiedData.isPresent() && verifiedData.get().equals(orderData)) {
    // Data is authentic and unmodified
    System.out.println("Order data verified successfully");
}
```

#### JWS Testing

The project includes comprehensive JWS testing with:
- **Signing Tests**: Verify JWS token creation
- **Verification Tests**: Ensure payload integrity
- **Security Tests**: Demonstrate tamper detection
- **Use Case Tests**: Real-world scenario validation
- **Wrong Key Tests**: Verify security properties

Run JWS tests with:
```bash
mvn test -Dtest=JwsTest
```

### JSON Web Encryption (JWE)

JSON Web Encryption (JWE) provides a means of representing encrypted content using JSON-based data structures. JWE in direct encryption mode provides three of the four fundamental cryptographic goals: integrity, authentication, and confidentiality.

#### JWE Implementation Features

- **AES-GCM Algorithm**: Uses AES-256-GCM for authenticated encryption
- **RFC 7516 Compliance**: Follows JSON Web Encryption standard
- **Five-Part Structure**: Implements header.encrypted_key.iv.ciphertext.tag format
- **Content Encryption**: Payload is completely encrypted and unreadable
- **Authentication Tag**: Ensures data integrity and authenticity

#### JWE Use Cases Demonstrated

1. **Encrypted Order Data Storage**
   - Encrypts sensitive order information
   - Provides complete confidentiality for stored data
   - Ensures data integrity through authentication tags

2. **Secure API Communication**
   - Encrypts complete API payloads
   - Hides sensitive data in transit
   - Prevents data interception and tampering

3. **Encrypted Configuration Files**
   - Secures configuration information
   - Protects database credentials and API keys
   - Ensures configuration integrity

4. **Secure Message Exchange**
   - Encrypts private communications
   - Provides end-to-end encryption
   - Ensures message authenticity and integrity

#### JWE Security Properties

| Security Property | Description | Implementation |
|-------------------|-------------|----------------|
| **Confidentiality** | Content is encrypted and unreadable without the key | AES-256-GCM encryption |
| **Integrity** | Any modification breaks decryption | Authentication tag verification |
| **Authentication** | Only holders of the correct key can decrypt | Key-based encryption/decryption |
| **Non-repudiation** | Not provided in direct mode | Cannot prove who encrypted content |

#### JWE Token Structure

```
eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0.encrypted_key.iv.ciphertext.tag
```

**Components:**
- **Header**: Algorithm and encryption method specification (`A256GCM`, `dir`)
- **Encrypted Key**: Content encryption key (empty in direct mode)
- **IV**: Initialization vector for AES-GCM
- **Ciphertext**: Encrypted payload content
- **Tag**: Authentication tag for integrity verification

#### JWE Implementation Example

```java
// Encrypt sensitive order data
String orderData = "{\"orders\":[{\"orderId\":\"12345\",\"amount\":500}]}";
String jweToken = CryptoUtils.encryptAsJwe(orderData, aesKey);

// Decrypt the content
String decryptedData = CryptoUtils.decryptJwe(jweToken, aesKey);
if (decryptedData.equals(orderData)) {
    // Data is confidential, authentic, and unmodified
    System.out.println("Order data decrypted successfully");
}
```

#### JWE Testing

The project includes comprehensive JWE testing with:
- **Encryption Tests**: Verify JWE token creation
- **Decryption Tests**: Ensure payload integrity and confidentiality
- **Security Tests**: Demonstrate tamper detection and wrong key failures
- **Use Case Tests**: Real-world scenario validation
- **Cryptographic Goals Tests**: Verify integrity, authentication, and confidentiality

Run JWE tests with:
```bash
mvn test -Dtest=JweTest
```

### When to Use JWS vs JWE

Understanding when to use JWS versus JWE is crucial for implementing the right security solution for your use case.

#### Similarities Between JWS and JWE

**Common Characteristics:**
- **JSON-based Structure**: Both use JSON for headers and payloads
- **RFC Standards**: Both follow IETF standards (JWS: RFC 7515, JWE: RFC 7516)
- **URL-safe Format**: Both use Base64 encoding for HTTP headers and URL parameters
- **Dot-separated Parts**: Both use periods to separate different components
- **Header Metadata**: Both include algorithm and encryption information in headers
- **Tamper Detection**: Both provide integrity protection (though through different mechanisms)

**Common Use Cases:**
- **API Communication**: Both can secure data in transit
- **Token-based Systems**: Both can be used for authentication and authorization
- **Data Validation**: Both ensure data hasn't been modified
- **Standard Compliance**: Both are widely supported across platforms

#### Key Differences

| Aspect | JWS (JSON Web Structure) | JWE (JSON Web Encryption) |
|--------|--------------------------|----------------------------|
| **Primary Purpose** | Digital signatures and authentication | Data encryption and confidentiality |
| **Content Visibility** | Payload is readable (Base64 encoded) | Payload is encrypted and unreadable |
| **Structure** | 3 parts: header.payload.signature | 5 parts: header.encrypted_key.iv.ciphertext.tag |
| **Algorithm** | HMAC-SHA256, RSA, ECDSA | AES-GCM, RSA-OAEP, ECDH-ES |
| **Key Type** | Symmetric (HMAC) or Asymmetric | Symmetric (AES) or Asymmetric |
| **Performance** | Faster (no encryption/decryption) | Slower (requires encryption/decryption) |

#### When to Use JWS

✅ **Use JWS when you need authentication and integrity, but NOT confidentiality**

- **JWT Tokens**: User sessions, API authentication
- **Signed Documents**: Contracts, certificates, configuration files
- **Audit Logs**: Events that need to be verifiable but readable
- **Public Data**: Information that should be accessible but tamper-proof
- **Performance Critical**: When speed is more important than secrecy

**Example JWS Use Case:**
```java
// API authentication token - readable but verifiable
String jwsToken = CryptoUtils.signJwsHmacSha256(apiRequest, secretKey);
// Result: eyJhbGciOiJIUzI1NiJ9.eyJtZXRob2QiOiJQT1NUIi... (readable payload)
```

#### When to Use JWE

✅ **Use JWE when you need confidentiality, integrity, AND authentication**

- **Sensitive Data**: Personal information, financial data, secrets
- **Secure Storage**: Encrypted configuration, encrypted databases
- **Private Communication**: Messages that should be completely hidden
- **Compliance Requirements**: When data must be encrypted at rest/transit
- **High Security**: When maximum protection is required

**Example JWE Use Case:**
```java
// Encrypted order data - completely hidden and secure
String jweToken = CryptoUtils.encryptAsJwe(sensitiveOrderData, aesKey);
// Result: eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0... (encrypted payload)
```

#### Security Properties Comparison

| Security Goal | JWS | JWE |
|---------------|-----|-----|
| **Integrity** | ✅ Yes (HMAC signature) | ✅ Yes (Authentication tag) |
| **Authentication** | ✅ Yes (Key-based signing) | ✅ Yes (Key-based encryption) |
| **Confidentiality** | ❌ No (payload readable) | ✅ Yes (AES encryption) |
| **Non-repudiation** | ✅ Yes (cryptographic proof) | ❌ No (in direct mode) |

#### Practical Decision Matrix

**Choose JWS if:**
```
Data is public or semi-public AND
You need to verify authenticity AND
You need to ensure integrity AND
Performance is important
```

**Choose JWE if:**
```
Data is sensitive or private AND
You need complete confidentiality AND
You need to ensure integrity AND
You need to verify authenticity AND
Security is more important than performance
```

#### Hybrid Approach

Sometimes you might want to use **both together**:

```java
// 1. First encrypt sensitive data with JWE
String encryptedData = CryptoUtils.encryptAsJwe(sensitiveOrderData, aesKey);

// 2. Then sign the encrypted data with JWS for authentication
String signedEncryptedData = CryptoUtils.signJwsHmacSha256(encryptedData, hmacKey);

// Result: JWS containing JWE - provides all 4 cryptographic goals!
```

#### Real-World Examples

**JWS Examples:**
- **OAuth 2.0 Access Tokens**: Need to be readable by clients
- **API Request Signing**: Verify request authenticity
- **Configuration Files**: Ensure settings haven't been tampered with
- **Event Logs**: Verify log entries are authentic

**JWE Examples:**
- **Encrypted API Payloads**: Hide sensitive request/response data
- **Secure Storage**: Encrypt database records, configuration secrets
- **Private Messaging**: Encrypt chat messages, emails
- **Financial Data**: Encrypt transaction details, account information

#### Summary

- **JWS**: "I can read this, and I know it's authentic and unmodified"
- **JWE**: "I can't read this, but I know it's authentic, unmodified, and confidential"

Choose based on whether you need **readability** (JWS) or **confidentiality** (JWE) for your specific use case!

## Security Properties and Technologies

This project demonstrates technologies that address the four fundamental security properties:

### Security Properties Overview

| Security Property | Definition | Technologies Used | Implementation |
|-------------------|------------|-------------------|----------------|
| **Integrity** | Ensures data has not been altered or corrupted during transmission or storage | • SHA-256 Message Digest<br>• MAC (Message Authentication Code)<br>• HMAC-SHA256<br>• AES-GCM (AEAD) | • `MessageDigest.SHA-256`<br>• Custom hash(key \|\| data)<br>• Google Tink HMAC<br>• Google Tink AES-GCM |
| **Authentication** | Verifies the identity of the sender or origin of data | • MAC<br>• HMAC-SHA256<br>• JWT with HMAC signing<br>• AES-GCM (AEAD) | • Custom keyed hash<br>• Google Tink HMAC<br>• Nimbus JOSE+JWT<br>• Google Tink AES-GCM |
| **Confidentiality** | Ensures data is accessible only to authorized parties | • AES-256-GCM encryption<br>• Associated Authenticated Encryption (AEAD) | • Google Tink AES-GCM<br>• Automatic key generation<br>• Secure ciphertext generation |
| **Non-repudiation** | Prevents the sender from denying they sent a message | • JWT with digital signatures<br>• HMAC-SHA256 for JWT signing<br>• Timestamped claims | • Nimbus JOSE+JWT<br>• HMAC-SHA256 signing<br>• JWT expiration claims |

### Detailed Technology Mapping

#### Integrity Technologies
- **SHA-256 Message Digest**: Provides data integrity verification without authentication
- **MAC**: Provides both integrity and authentication using a shared secret key
- **HMAC-SHA256**: Standardized MAC algorithm providing integrity and authentication
- **AES-GCM**: Provides integrity through authenticated encryption

#### Authentication Technologies
- **MAC/HMAC**: Verifies data origin using shared secret keys
- **JWT with HMAC**: Provides authentication through signed tokens
- **AES-GCM**: Provides authentication through associated data verification

#### Confidentiality Technologies
- **AES-256-GCM**: Symmetric encryption providing data confidentiality
- **Google Tink**: Provides secure key management and encryption primitives
- **AEAD**: Ensures both confidentiality and integrity in one operation

#### Non-repudiation Technologies
- **JWT with HMAC-SHA256**: Provides proof of message origin and integrity
- **Timestamped Claims**: JWT expiration and issued-at timestamps
- **Digital Signatures**: HMAC-based signatures for JWT tokens

### Security Property Coverage

| Technology | Integrity | Authentication | Confidentiality | Non-repudiation |
|------------|-----------|----------------|-----------------|-----------------|
| **SHA-256** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **MAC** | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **HMAC-SHA256** | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **AES-GCM** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **JWT + HMAC** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| **JWS** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| **JWE** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |

### Use Case Examples

#### File Integrity Verification
```java
// Integrity only - SHA-256
String fileHash = sha256(fileContent);
// Use case: File checksums, blockchain hashes
```

#### API Authentication
```java
// Integrity + Authentication - HMAC
String signature = hmacSha256(requestBody, secretKey);
// Use case: API request signing, secure communication
```

#### Data Encryption
```java
// Integrity + Authentication + Confidentiality - AES-GCM
byte[] ciphertext = aesGcm.encrypt(plaintext, associatedData);
// Use case: Secure data storage, encrypted communication
```

#### Token-based Authentication
```java
// Integrity + Authentication + Non-repudiation - JWT + HMAC
SignedJWT jwt = new SignedJWT(header, claims);
jwt.sign(hmacSigner);
// Use case: User sessions, API authentication, SSO
```

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

#### JWS Tests
```bash
mvn test -Dtest=JwsTest
```

#### JWE Tests
```bash
mvn test -Dtest=JweTest
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
