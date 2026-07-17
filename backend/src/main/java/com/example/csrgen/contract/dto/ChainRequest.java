package com.example.csrgen.contract.dto;

/**
 * Request for the chain builder: a blob of PEM certificates in any order
 * (extra text between blocks is ignored).
 */
public record ChainRequest(String certificates) {
}
