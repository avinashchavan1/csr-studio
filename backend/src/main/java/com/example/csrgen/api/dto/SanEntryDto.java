package com.example.csrgen.api.dto;

import com.example.csrgen.domain.SanType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * A single Subject Alternative Name entry.
 */
public record SanEntryDto(
        @NotNull SanType type,
        @NotBlank String value
) {
}
