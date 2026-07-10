package com.example.csrgen.contract.dto;

/**
 * POST /csr/sign 200 response. Returns the signature (base64 + hex) and the derived
 * public key PEM so the result can be verified immediately.
 */
public record SignResponse(
        String signature,      // base64
        String signatureHex,
        String publicKey,      // derived PEM (null if it couldn't be derived)
        String algorithm,
        String keyKind,
        boolean pqc
) {
}
