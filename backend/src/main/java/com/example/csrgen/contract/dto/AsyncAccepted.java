package com.example.csrgen.contract.dto;

/**
 * 202 Accepted body for an async generate job.
 */
public record AsyncAccepted(
        String jobId,
        String statusUrl,
        String status
) {
}
