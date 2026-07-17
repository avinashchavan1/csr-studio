package com.example.csrgen.contract.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * Every representation of a key we can compute from the pasted input.
 * Private-key fields are only present when a private key was pasted.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record KeyConvertResponse(
        String inputType,          // "private-key" | "public-key" | "certificate" | "csr"
        String keyKind,            // RSA | EC | ED25519 | ML-DSA | SLH-DSA | Falcon
        String keyDetail,          // "2048-bit" | "P-256" | "ML-DSA-65" ...
        boolean pqc,
        String pkcs8Pem,           // private key, PKCS#8 armor
        String traditionalPem,     // RSA→PKCS#1, EC→SEC1; null otherwise
        String pkcs8DerBase64,     // private key DER, base64 (for .der download)
        String publicPem,          // SubjectPublicKeyInfo
        String publicDerBase64,
        Map<String, String> jwk,   // public JWK (RSA/EC/Ed25519 only)
        String sshPublicKey,       // OpenSSH one-liner (RSA/EC/Ed25519 only)
        String spkiSha256,         // hex-colon SHA-256 of the SPKI
        String spkiPin,            // base64 SPKI pin (HPKP style)
        String sshFingerprint,     // OpenSSH "SHA256:..." fingerprint
        List<String> warnings) {
}
