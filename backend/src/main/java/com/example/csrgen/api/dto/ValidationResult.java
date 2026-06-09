package com.example.csrgen.api.dto;

import java.util.List;

/**
 * Outcome of running policy + integrity checks against a CSR.
 */
public record ValidationResult(
        boolean valid,
        List<String> errors,
        List<String> warnings
) {
}
