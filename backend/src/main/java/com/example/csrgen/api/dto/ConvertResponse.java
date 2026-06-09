package com.example.csrgen.api.dto;

/**
 * Conversion output. Exactly one of pem / derBase64 is populated.
 */
public record ConvertResponse(
        ConvertRequest.Format format,
        String pem,
        String derBase64
) {
}
