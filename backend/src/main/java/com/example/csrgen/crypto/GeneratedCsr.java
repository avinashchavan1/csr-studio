package com.example.csrgen.crypto;

/**
 * A generated CSR plus its private key (already PEM-encoded) and the signature
 * algorithm used. The private key encoding (PKCS#1 vs PKCS#8) is decided by the caller.
 */
public record GeneratedCsr(
        String csrPem,
        String keyPem,
        String signatureAlgorithm
) {
}
