package com.example.csrgen.api.dto;

import java.util.List;
import java.util.Map;

/**
 * Decoded view of a PKCS#10 CSR.
 */
public record CsrParseResponse(
        String subjectDn,
        Map<String, String> subjectFields,
        List<SanEntryDto> subjectAltNames,
        String keyAlgorithm,
        Integer keySize,
        String signatureAlgorithm,
        boolean signatureValid,
        List<String> keyUsages,
        List<String> extendedKeyUsages,
        String basicConstraints
) {
    /** Back-compat constructor for callers/tests that predate extension extraction. */
    public CsrParseResponse(String subjectDn, Map<String, String> subjectFields,
                            List<SanEntryDto> subjectAltNames, String keyAlgorithm, Integer keySize,
                            String signatureAlgorithm, boolean signatureValid) {
        this(subjectDn, subjectFields, subjectAltNames, keyAlgorithm, keySize,
                signatureAlgorithm, signatureValid, null, null, null);
    }
}
