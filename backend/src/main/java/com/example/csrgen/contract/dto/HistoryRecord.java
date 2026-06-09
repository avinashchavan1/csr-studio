package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

/**
 * A saved CSR history entry. On create, {@code id} and {@code createdAt} are ignored
 * (server-assigned). Never carries a private key — keys are not persisted server-side.
 */
public record HistoryRecord(
        String id,
        String commonName,
        String organization,
        String keyLabel,
        String keyDetail,
        String keyFormat,
        String signatureAlgorithm,
        List<ContractSan> sans,
        @NotBlank String csrPem,
        Long createdAt
) {
}
