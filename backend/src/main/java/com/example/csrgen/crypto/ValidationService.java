package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrParseResponse;
import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.ValidationResult;
import com.example.csrgen.domain.KeyAlgorithm;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Enforces cryptographic strength and algorithm policy on incoming requests.
 */
@Service
public class ValidationService {

    private static final int MIN_RSA_SIZE = 2048;
    private static final Set<Integer> ALLOWED_RSA_SIZES = Set.of(2048, 3072, 4096);
    private static final Set<String> ALLOWED_EC_CURVES = Set.of("P-256", "P-384", "P-521");
    private static final Set<String> WEAK_SIG_ALGOS = Set.of("MD5", "SHA1");

    public void validate(CsrRequest req) {
        if (req.keyAlgorithm() == KeyAlgorithm.RSA) {
            int size = req.keySize() != null ? req.keySize() : MIN_RSA_SIZE;
            if (size < MIN_RSA_SIZE) {
                throw new CryptoException("RSA key size must be >= " + MIN_RSA_SIZE);
            }
            if (!ALLOWED_RSA_SIZES.contains(size)) {
                throw new CryptoException("RSA key size must be one of " + ALLOWED_RSA_SIZES);
            }
        }
        if (req.keyAlgorithm() == KeyAlgorithm.EC && req.ecCurve() != null
                && !ALLOWED_EC_CURVES.contains(req.ecCurve())) {
            throw new CryptoException("EC curve must be one of " + ALLOWED_EC_CURVES);
        }
        if (req.signatureAlgorithm() != null) {
            String upper = req.signatureAlgorithm().toUpperCase();
            for (String weak : WEAK_SIG_ALGOS) {
                if (upper.startsWith(weak)) {
                    throw new CryptoException("Weak signature algorithm rejected: "
                            + req.signatureAlgorithm());
                }
            }
        }
    }

    /**
     * Runs policy + integrity checks against an already-parsed CSR and reports
     * all findings, rather than throwing on the first failure.
     */
    public ValidationResult validateParsed(CsrParseResponse csr) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (!csr.signatureValid()) {
            errors.add("CSR signature is invalid");
        }
        boolean hasCn = csr.subjectFields().containsKey("commonName");
        boolean hasSanEarly = csr.subjectAltNames() != null && !csr.subjectAltNames().isEmpty();
        if (!hasCn && !hasSanEarly) {
            errors.add("No Common Name and no Subject Alternative Names");
        } else if (!hasCn) {
            warnings.add("No Common Name (CN) — acceptable for modern SAN-only certificates");
        }

        String sig = csr.signatureAlgorithm() != null ? csr.signatureAlgorithm().toUpperCase() : "";
        for (String weak : WEAK_SIG_ALGOS) {
            if (sig.contains(weak)) {
                errors.add("Weak signature algorithm: " + csr.signatureAlgorithm());
            }
        }

        if ("RSA".equals(csr.keyAlgorithm()) && csr.keySize() != null) {
            if (csr.keySize() < MIN_RSA_SIZE) {
                errors.add("RSA key too small: " + csr.keySize() + " (min " + MIN_RSA_SIZE + ")");
            } else if (csr.keySize() < 3072) {
                warnings.add("RSA " + csr.keySize() + " is acceptable; 3072+ recommended");
            }
        }

        boolean hasSan = csr.subjectAltNames() != null && !csr.subjectAltNames().isEmpty();
        if (!hasSan) {
            warnings.add("No Subject Alternative Names; modern TLS clients require SANs");
        }

        return new ValidationResult(errors.isEmpty(), errors, warnings);
    }
}
