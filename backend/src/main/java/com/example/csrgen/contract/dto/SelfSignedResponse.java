package com.example.csrgen.contract.dto;

/**
 * POST /csr/self-signed response: a self-signed X.509 certificate plus the CSR and key
 * it was issued from. For testing only — not CA-issued.
 */
public record SelfSignedResponse(
        String certificate,
        String privateKey,
        String csr,
        GenerateResponse.Details details
) {
}
