package com.example.csrgen.contract.dto;

import java.util.List;

/**
 * POST /csr/decode 200 response.
 */
public record DecodeResponse(
        ContractSubject subject,
        List<ContractSan> subjectAltNames,
        Key key,
        Signature signature
) {
    public record Key(String kind, String detail, Integer bits) {
    }

    public record Signature(String algorithm, Boolean valid) {
    }
}
