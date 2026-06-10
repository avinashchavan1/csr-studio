package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Subject fields as named in the CSR Studio API contract.
 */
public record ContractSubject(
        @NotBlank(message = "Common Name is required.")
        @Size(max = 253, message = "Common Name is too long.") String commonName,
        @Size(max = 64) String organization,
        @Size(max = 64) String organizationalUnit,
        @Size(max = 128) String locality,
        @Size(max = 128) String state,
        @Pattern(regexp = "^([A-Za-z]{2})?$", message = "Country must be a 2-letter ISO 3166 code.")
        String country,
        @Email(message = "Enter a valid email address.")
        @Size(max = 254) String email
) {
}
