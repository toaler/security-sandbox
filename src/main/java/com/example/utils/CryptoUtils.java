package com.example.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for cryptographic operations.
 */
public class CryptoUtils {
    
    /**
     * Generates SHA-256 hash of the provided content.
     * 
     * @param content the byte array to hash
     * @return the SHA-256 hash as a hexadecimal string
     * @throws RuntimeException if SHA-256 algorithm is not available
     */
    public static String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    
    /**
     * Converts a byte array to a hexadecimal string.
     * 
     * @param bytes the byte array to convert
     * @return the hexadecimal string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
