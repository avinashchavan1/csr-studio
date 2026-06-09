package com.example.csrgen.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Convert a payload between PEM and DER.
 *
 * <p>For PEM->DER set {@code pem}. For DER->PEM set {@code derBase64} and {@code pemType}
 * (e.g. "CERTIFICATE REQUEST", "CERTIFICATE", "PUBLIC KEY").
 */
public record ConvertRequest(
        @NotNull Format from,
        @NotNull Format to,
        String pem,
        String derBase64,
        String pemType
) {
    public enum Format {
        PEM,
        DER
    }
}
