package com.example.csrgen.contract.dto;

import java.util.List;

/**
 * POST /csr/decode 200 response.
 */
public record DecodeResponse(
        ContractSubject subject,
        List<ContractSan> subjectAltNames,
        Key key,
        Signature signature,
        Extensions extensions
) {
    public record Key(String kind, String detail, Integer bits) {
    }

    public record Signature(String algorithm, Boolean valid) {
    }

    /** Extension requests found in the CSR (null entries when absent). */
    public record Extensions(
            List<String> keyUsage,
            List<String> extendedKeyUsage,
            String basicConstraints
    ) {
    }
}
