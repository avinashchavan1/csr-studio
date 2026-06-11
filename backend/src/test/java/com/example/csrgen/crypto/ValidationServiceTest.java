package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrParseResponse;
import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.SanEntryDto;
import com.example.csrgen.api.dto.ValidationResult;
import com.example.csrgen.domain.KeyAlgorithm;
import com.example.csrgen.domain.SanType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ValidationServiceTest {

    private final ValidationService v = new ValidationService();

    @Test
    void rejectsWeakRsaKey() {
        CsrRequest req = new CsrRequest(KeyAlgorithm.RSA, 1024, null,
                CryptoTestSupport.subject("a.com"), List.of(), null);
        assertThatThrownBy(() -> v.validate(req))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("2048");
    }

    @Test
    void rejectsWeakSignatureAlgorithm() {
        CsrRequest req = new CsrRequest(KeyAlgorithm.RSA, 2048, null,
                CryptoTestSupport.subject("a.com"), List.of(), "SHA1withRSA");
        assertThatThrownBy(() -> v.validate(req)).isInstanceOf(CryptoException.class);
    }

    @Test
    void parsedValidationFlagsMissingCnAndWeakKey() {
        CsrParseResponse parsed = new CsrParseResponse(
                "CN=", Map.of(), List.of(), "RSA", 1024, "SHA256WITHRSA", true);
        ValidationResult r = v.validateParsed(parsed);
        assertThat(r.valid()).isFalse();
        assertThat(r.errors()).anyMatch(e -> e.contains("No Common Name"));
        assertThat(r.errors()).anyMatch(e -> e.contains("too small"));
    }

    @Test
    void parsedValidationWarnsOnRsa2048AndNoSan() {
        CsrParseResponse parsed = new CsrParseResponse(
                "CN=a.com", Map.of("commonName", "a.com"),
                List.of(), "RSA", 2048, "SHA256WITHRSA", true);
        ValidationResult r = v.validateParsed(parsed);
        assertThat(r.valid()).isTrue();
        assertThat(r.warnings()).anyMatch(w -> w.contains("3072"));
        assertThat(r.warnings()).anyMatch(w -> w.contains("SAN"));
    }

    @Test
    void parsedValidationFailsOnInvalidSignature() {
        CsrParseResponse parsed = new CsrParseResponse(
                "CN=a.com", Map.of("commonName", "a.com"),
                List.of(new SanEntryDto(SanType.DNS, "a.com")), "RSA", 3072, "SHA256WITHRSA", false);
        ValidationResult r = v.validateParsed(parsed);
        assertThat(r.valid()).isFalse();
        assertThat(r.errors()).anyMatch(e -> e.toLowerCase().contains("signature"));
    }
}
