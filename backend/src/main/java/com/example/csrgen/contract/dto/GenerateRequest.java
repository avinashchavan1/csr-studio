package com.example.csrgen.contract.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * POST /csr/generate request body.
 */
public record GenerateRequest(
        @NotNull @Valid ContractSubject subject,
        @Valid List<ContractSan> subjectAltNames,
        @NotNull @Valid ContractKey key,
        String signatureHash
) {
}
