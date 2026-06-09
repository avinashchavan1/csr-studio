package com.example.csrgen.contract.dto;

public record MatchResponse(
        boolean supported,
        boolean match,
        Integer bits
) {
}
