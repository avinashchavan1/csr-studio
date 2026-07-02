package com.example.csrgen.contract.dto;

import java.util.List;

/**
 * Quantum-readiness report for a CSR / certificate / live host.
 */
public record QuantumScanResponse(
        String target,               // what was scanned (subject or host)
        String keyAlgorithm,
        String keyDetail,
        String signatureAlgorithm,
        boolean quantumVulnerable,   // breakable by Shor-capable quantum computer
        String grade,                // A+ (PQC) … F (broken classical)
        int score,                   // 0 (safe) … 100 (max exposure)
        String hndlRisk,             // harvest-now-decrypt-later exposure: none|low|medium|high
        List<String> findings,
        String recommendation,
        String notAfter              // cert expiry (certificates / hosts only)
) {
}
