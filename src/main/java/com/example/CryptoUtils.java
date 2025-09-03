package com.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Optional;

/**
 * Utility class for cryptographic operations including JSON Web Signatures (JWS).
 */
public class CryptoUtils {
    
    /**
     * Signs content using HMAC-SHA256 algorithm and returns a JWS token.
     * 
     * @param content The content to sign
     * @param key The secret key for HMAC signing
     * @return A serialized JWS token
     * @throws RuntimeException if signing fails
     */
    public static String signJwsHmacSha256(String content, byte[] key) {
        try {
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256); // #A
            Payload payload = new Payload(content);
            JWSObject jwsObject = new JWSObject(header, payload);
            jwsObject.sign(new MACSigner(key)); // #B
            return jwsObject.serialize(); // #C
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Verifies a JWS token using HMAC-SHA256.
     * 
     * @param jwsToken The JWS token to verify
     * @param key The secret key for verification
     * @return Optional containing the payload if verification succeeds, empty otherwise
     */
    public static Optional<String> verifyJwsHmacSha256(String jwsToken, byte[] key) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwsToken);
            JWSVerifier verifier = new MACVerifier(key);
            
            if (jwsObject.verify(verifier)) {
                return Optional.of(jwsObject.getPayload().toString());
            }
            return Optional.empty();
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }
    
    /**
     * Extracts the payload from a JWS token without verification.
     * 
     * @param jwsToken The JWS token to parse
     * @return Optional containing the payload if parsing succeeds, empty otherwise
     */
    public static Optional<String> extractJwsPayload(String jwsToken) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwsToken);
            return Optional.of(jwsObject.getPayload().toString());
        } catch (ParseException e) {
            return Optional.empty();
        }
    }
    
    /**
     * Checks if a string is a valid JWS token format.
     * 
     * @param token The token to validate
     * @return true if the token appears to be a valid JWS format
     */
    public static boolean isValidJwsFormat(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        
        // JWS tokens have three parts separated by dots
        String[] parts = token.split("\\.");
        return parts.length == 3;
    }
    
    /**
     * Encrypts content as a JWE using AES-GCM with a 256-bit key.
     * 
     * @param content The content to encrypt
     * @param key The AES key for encryption (must be 256 bits)
     * @return A serialized JWE token
     * @throws RuntimeException if encryption fails
     */
    public static String encryptAsJwe(String content, byte[] key) {
        try {
            var header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
            var payload = new Payload(content); // #A
            var jweObject = new JWEObject(header, payload); // #A
            var aesKey = new SecretKeySpec(key, "AES"); // #B
            jweObject.encrypt(new DirectEncrypter(aesKey)); // #B
            return jweObject.serialize(); // #C
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Decrypts a JWE token using AES-GCM with a 256-bit key.
     * 
     * @param jwe The JWE token to decrypt
     * @param key The AES key for decryption (must be 256 bits)
     * @return The decrypted content
     * @throws RuntimeException if decryption fails
     */
    public static String decryptJwe(String jwe, byte[] key) {
        try {
            JWEObject jweObject = JWEObject.parse(jwe); // #A
            SecretKeySpec aesKey = new SecretKeySpec(key, "AES"); // #B
            jweObject.decrypt(new DirectDecrypter(aesKey)); // #B
            Payload payload = jweObject.getPayload(); // #C
            return payload.toString(); // #C
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Checks if a string is a valid JWE token format.
     * 
     * @param token The token to validate
     * @return true if the token appears to be a valid JWE format
     */
    public static boolean isValidJweFormat(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        
        // JWE tokens have five parts separated by dots
        // header.encrypted_key.iv.ciphertext.tag
        String[] parts = token.split("\\.");
        return parts.length == 5;
    }
    
    /**
     * Extracts the header from a JWE token without decryption.
     * 
     * @param jweToken The JWE token to parse
     * @return Optional containing the header if parsing succeeds, empty otherwise
     */
    public static Optional<String> extractJweHeader(String jweToken) {
        try {
            JWEObject jweObject = JWEObject.parse(jweToken);
            return Optional.of(jweObject.getHeader().toString());
        } catch (ParseException e) {
            return Optional.empty();
        }
    }
} 