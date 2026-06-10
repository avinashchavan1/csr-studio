package com.example.csrgen.api.dto;

import com.example.csrgen.domain.KeyAlgorithm;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Request to generate a key pair + CSR.
 *
 * <p>keySize meaning depends on algorithm:
 * <ul>
 *   <li>RSA - bits (2048, 3072, 4096)</li>
 *   <li>EC  - ignored; curve name carried in ecCurve</li>
 *   <li>ED25519 - ignored</li>
 * </ul>
 */
public record CsrRequest(
        @NotNull KeyAlgorithm keyAlgorithm,
        Integer keySize,
        String ecCurve,
        @NotNull @Valid SubjectDto subject,
        @Valid List<SanEntryDto> subjectAltNames,
        String signatureAlgorithm,
        List<String> keyUsages,
        List<String> extendedKeyUsages,
        Boolean caConstraint,
        Integer pathLenConstraint
) {
    /** Back-compat: no extensions at all. */
    public CsrRequest(KeyAlgorithm keyAlgorithm, Integer keySize, String ecCurve,
                      SubjectDto subject, List<SanEntryDto> subjectAltNames, String signatureAlgorithm) {
        this(keyAlgorithm, keySize, ecCurve, subject, subjectAltNames, signatureAlgorithm, null, null, null, null);
    }

    /** Back-compat: key usages / EKU but no basicConstraints. */
    public CsrRequest(KeyAlgorithm keyAlgorithm, Integer keySize, String ecCurve,
                      SubjectDto subject, List<SanEntryDto> subjectAltNames, String signatureAlgorithm,
                      List<String> keyUsages, List<String> extendedKeyUsages) {
        this(keyAlgorithm, keySize, ecCurve, subject, subjectAltNames, signatureAlgorithm,
                keyUsages, extendedKeyUsages, null, null);
    }
}
