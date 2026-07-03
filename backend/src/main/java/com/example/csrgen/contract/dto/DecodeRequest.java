package com.example.csrgen.contract.dto;

import jakarta.validation.constraints.NotBlank;

public record DecodeRequest(
        @NotBlank(message = "Nothing to decode. Paste a certificate signing request — the full PEM block "
                + "(\"-----BEGIN CERTIFICATE REQUEST-----\") or just its base64 body.")
        String csr
) {
}
