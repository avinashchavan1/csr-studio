package com.example.csrgen.contract.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * GET /csr/jobs/{jobId} response. Null fields are omitted.
 *
 * <p>status is one of: queued | processing | done | error.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JobStatusResponse(
        String status,
        Double progress,
        String message,
        GenerateResponse result,
        Error error
) {
    public record Error(String message) {
    }
}
