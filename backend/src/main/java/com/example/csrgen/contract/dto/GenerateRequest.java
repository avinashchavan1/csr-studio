package com.example.csrgen.contract.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * POST /csr/generate request body.
 */
public record GenerateRequest(
        @NotNull(message = "Subject is required.") @Valid ContractSubject subject,
        @Valid List<ContractSan> subjectAltNames,
        @NotNull(message = "Key options are required.") @Valid ContractKey key,
        String signatureHash,
        Extensions extensions
) {
    /** Back-compat constructor for callers that don't request extensions. */
    public GenerateRequest(ContractSubject subject, List<ContractSan> subjectAltNames,
                           ContractKey key, String signatureHash) {
        this(subject, subjectAltNames, key, signatureHash, null);
    }

    /** Optional X.509 v3 extension requests carried in the CSR. */
    public record Extensions(
            List<String> keyUsage,
            List<String> extendedKeyUsage,
            Boolean basicConstraintsCa,
            Integer basicConstraintsPathLen
    ) {
        /** Back-compat: keyUsage/EKU only. */
        public Extensions(List<String> keyUsage, List<String> extendedKeyUsage) {
            this(keyUsage, extendedKeyUsage, null, null);
        }
    }
}
