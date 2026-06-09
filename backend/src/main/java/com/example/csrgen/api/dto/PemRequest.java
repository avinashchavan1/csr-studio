package com.example.csrgen.api.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * A request carrying a single PEM payload (e.g. a CSR to parse or validate).
 */
public record PemRequest(
        @NotBlank String pem
) {
}
