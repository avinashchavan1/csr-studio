package com.example.csrgen.contract.dto;

/**
 * POST /csr/sign request — sign a message with a private key. The private key is
 * used transiently to produce the signature and is never stored.
 */
public record SignRequest(
        String message,
        String messageEncoding,   // "utf8" (default) | "base64" | "hex"
        String privateKey,        // PEM (PKCS#8 or PKCS#1)
        String algorithm,         // "auto" (default) | explicit JCA name
        String hash,              // optional: SHA-256 (default) / SHA-384 / SHA-512
        Boolean rsaPss            // optional: RSA-PSS instead of PKCS#1 v1.5
) {
}
