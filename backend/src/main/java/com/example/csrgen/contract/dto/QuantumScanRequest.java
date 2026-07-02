package com.example.csrgen.contract.dto;

/**
 * POST /csr/quantum-scan input — exactly one of:
 * a PEM CSR, a PEM certificate, or a hostname (its live TLS leaf cert is fetched).
 */
public record QuantumScanRequest(
        String csr,
        String certificate,
        String host
) {
}
