package com.example.csrgen.api.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

/**
 * Bundle a certificate + private key (+ optional CA chain) into a PKCS#12 (.p12/.pfx).
 */
public record Pkcs12Request(
        @NotBlank String certificatePem,
        @NotBlank String privateKeyPem,
        List<String> caChainPem,
        String alias,
        @NotBlank String password
) {
}
