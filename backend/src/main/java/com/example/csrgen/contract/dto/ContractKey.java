package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Key spec from the contract.
 *
 * <ul>
 *   <li>RSA   → algorithm "RSA", size 2048/3072/4096, format "PKCS#8"|"PKCS#1"</li>
 *   <li>ECDSA → algorithm "ECDSA", curve "P-256"|"P-384", format "PKCS#8"</li>
 * </ul>
 */
public record ContractKey(
        @NotBlank String algorithm,
        Integer size,
        String curve,
        String format,
        Boolean rsaPss
) {
    /** Back-compat: no PSS flag. */
    public ContractKey(String algorithm, Integer size, String curve, String format) {
        this(algorithm, size, curve, format, null);
    }
}
