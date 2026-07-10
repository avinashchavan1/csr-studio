package com.example.csrgen.contract.dto;

/**
 * POST /csr/verify request. Two modes:
 *
 * <ul>
 *   <li>{@code detached} — verify a signature over a message/bytes with a public key
 *       or certificate.</li>
 *   <li>{@code issuer} — verify a leaf certificate was signed by a given issuer/CA
 *       certificate.</li>
 * </ul>
 *
 * All verification is public-key math: no private key is involved and nothing is stored.
 */
public record VerifyRequest(
        String mode,                  // "detached" (default) | "issuer"

        // --- detached mode ---
        String message,
        String messageEncoding,       // "utf8" (default) | "base64" | "hex"
        String signature,
        String signatureEncoding,     // "base64" (default) | "hex"
        String publicKey,             // PEM (SubjectPublicKeyInfo) — or use certificate
        String algorithm,             // "auto" (default) | explicit JCA name
        String hash,                  // optional: SHA-256 (default) / SHA-384 / SHA-512
        Boolean rsaPss,               // optional: RSA-PSS instead of PKCS#1 v1.5

        // --- shared / issuer mode ---
        String certificate,           // detached: verifier cert · issuer: the leaf cert
        String issuerCertificate      // issuer mode: the signing CA cert
) {
}
