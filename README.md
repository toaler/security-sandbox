# Security Sandbox

A Java 21 Maven project demonstrating cryptographic libraries and security testing capabilities.

## Project Overview

This project serves as a sandbox environment for exploring and testing various security-related Java libraries:

- **Google Tink**: Cryptographic library for encryption/decryption
- **Nimbus JOSE+JWT**: JWT (JSON Web Token) creation and verification
- **JUnit 5**: Latest version for unit testing
- **AssertJ**: Fluent assertion library for readable tests

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
│       │       └── AppTest.java     # Test examples
│       └── resources/               # Test resources
```

## Dependencies

### Core Dependencies
- **Google Tink** (v1.12.0): Cryptographic library for encryption/decryption operations
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

### Testing with JUnit 5 and AssertJ
The test suite demonstrates:
- Nested test classes
- Descriptive test names with `@DisplayName`
- Fluent assertions with AssertJ
- Exception testing
- Collection and string assertions

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

## Contributing

Feel free to extend this sandbox with additional security libraries and examples. Some ideas:
- Bouncy Castle cryptography
- Spring Security integration
- OAuth2/OIDC examples
- Certificate handling
- Secure random number generation

## License

This project is for educational purposes. Use at your own risk.
