package com.example.csrgen.contract.dto;

/**
 * A Subject Alternative Name entry: type is "DNS" or "IP".
 */
public record ContractSan(
        String type,
        String value
) {
}
