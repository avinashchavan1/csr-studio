package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

public record DecodeRequest(
        @NotBlank String csr
) {
}
