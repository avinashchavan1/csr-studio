package com.example.csrgen.contract.dto;

/**
 * POST /csr/verify 200 response. Fields not relevant to the mode are null.
 */
public record VerifyResponse(
        boolean valid,
        String mode,
        String algorithm,     // resolved signature algorithm (e.g. "SHA256withECDSA", "ML-DSA-65")
        String keyKind,       // RSA | EC | ED25519 | ML-DSA | SLH-DSA | Falcon
        boolean pqc,
        String reason,        // human explanation when invalid / on soft failure

        // issuer mode extras (null in detached mode)
        String subject,
        String issuer,
        Long notBefore,
        Long notAfter,
        Boolean timeValid,
        Boolean nameChainOk
) {
    /** Detached-mode result. */
    public static VerifyResponse detached(boolean valid, String algorithm, String keyKind,
                                          boolean pqc, String reason) {
        return new VerifyResponse(valid, "detached", algorithm, keyKind, pqc, reason,
                null, null, null, null, null, null);
    }
}
