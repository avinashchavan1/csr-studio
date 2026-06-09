package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Subject fields as named in the CSR Studio API contract.
 */
public record ContractSubject(
        @NotBlank(message = "Common Name is required.") String commonName,
        String organization,
        String organizationalUnit,
        String locality,
        String state,
        String country,
        String email
) {
}
