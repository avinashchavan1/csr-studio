package com.example.csrgen.contract.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Result of building + validating a certificate chain from a pasted bundle.
 * {@code chain} is ordered leaf → root; {@code links} holds the checks for each
 * child→parent step.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChainResponse(
        List<ChainCert> chain,
        List<ChainLink> links,
        boolean complete,          // reached a self-signed root
        boolean allValid,          // complete + every signature/time/CA check passed
        String missingIssuer,      // issuer DN we couldn't find (when incomplete)
        String missingIssuerUrl,   // AIA "CA Issuers" URL to fetch it, if the cert names one
        List<ChainCert> extras,    // parsed certs that aren't part of the path
        List<String> warnings,
        String orderedPem) {       // the corrected leaf→root bundle

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ChainCert(
            int index,
            String subject,
            String issuer,
            String serialHex,
            String notBefore,
            String notAfter,
            boolean expired,
            boolean notYetValid,
            boolean selfSigned,
            boolean ca,
            Integer pathLen,
            String keyKind,
            String keyDetail,
            boolean pqc,
            String signatureAlgorithm,
            String sha256) {
    }

    /** Checks for one child→parent step of the chain. */
    public record ChainLink(
            int childIndex,
            int parentIndex,
            boolean signatureValid,
            boolean issuerIsCa,
            boolean issuerCanSignCerts,
            boolean nameChainOk) {
    }
}
