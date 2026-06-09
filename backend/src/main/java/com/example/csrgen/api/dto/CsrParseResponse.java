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
        boolean signatureValid
) {
}
