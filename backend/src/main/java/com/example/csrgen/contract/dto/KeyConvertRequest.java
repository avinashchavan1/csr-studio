package com.example.csrgen.contract.dto;

/**
 * Request for the key/format converter. {@code input} is any PEM (private key,
 * public key, certificate or CSR) — or bare base64 DER of one of those.
 */
public record KeyConvertRequest(String input) {
}
