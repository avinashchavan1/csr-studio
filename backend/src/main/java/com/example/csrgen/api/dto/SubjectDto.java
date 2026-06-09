package com.example.csrgen.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Distinguished Name fields for the CSR subject.
 * Only commonName is required; the rest are optional.
 */
public record SubjectDto(
        @NotBlank @Size(max = 64) String commonName,
        @Size(max = 64) String organization,
        @Size(max = 64) String organizationalUnit,
        @Size(max = 128) String locality,
        @Size(max = 128) String state,
        @Size(max = 2, min = 2) String country,
        @Size(max = 128) String email
) {
}
