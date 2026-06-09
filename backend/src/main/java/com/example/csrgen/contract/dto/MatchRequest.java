package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

public record MatchRequest(
        @NotBlank String csr,
        @NotBlank String privateKey
) {
}
