package com.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
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
} 