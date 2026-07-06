package com.example.csrgen.contract.dto;

/**
 * POST /csr/generate 200 response.
 */
public record GenerateResponse(
        String csr,
        String privateKey,
        Details details,
        String id,
        String recordPath
) {
    public record Details(
            String keyLabel,
            String keyDetail,
            String keyFormat,
            String signatureAlgorithm
    ) {
    }
}
