package com.example.csrgen.api.error;

import java.time.Instant;

/**
 * Standard error response body.
 */
public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String message
) {
    public static ApiError of(int status, String error, String message) {
        return new ApiError(Instant.now(), status, error, message);
    }
}
