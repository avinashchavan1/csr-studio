package com.example.csrgen.api.dto;

/**
 * Result of CSR generation.
 *
 * <p>WARNING: privateKeyPem is returned here for the dev/test milestone only.
 * In production the private key must stay in a KMS/HSM and never cross the wire.
 */
public record CsrResponse(
        String csrPem,
        String publicKeyPem,
        String privateKeyPem,
        String keyAlgorithm,
        String signatureAlgorithm
) {
}
