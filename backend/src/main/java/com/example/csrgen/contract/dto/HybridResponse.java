package com.example.csrgen.contract.dto;

/**
 * POST /csr/hybrid response: a matched pair of CSRs for the same identity —
 * a classical one (RSA/ECDSA, accepted by today's CAs) and a post-quantum one
 * (ML-DSA/SLH-DSA/Falcon) for crypto-agility / PQC migration.
 */
public record HybridResponse(
        GenerateResponse classical,
        GenerateResponse pqc
) {
}
