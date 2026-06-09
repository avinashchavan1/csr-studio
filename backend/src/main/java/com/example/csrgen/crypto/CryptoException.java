package com.example.csrgen.crypto;

/**
 * Thrown when a crypto operation fails or input violates policy.
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
