package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrParseResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CsrParserTest {

    private final CsrService csr = CryptoTestSupport.csrService();
    private final CsrParser parser = new CsrParser();

    @Test
    void parsesSubjectSanKeyAndSignature() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("shop.example.com"), false);
        CsrParseResponse p = parser.parse(g.csrPem());

        assertThat(p.subjectFields())
                .containsEntry("commonName", "shop.example.com")
                .containsEntry("organization", "Example Inc")
                .containsEntry("country", "US");
        assertThat(p.subjectAltNames()).extracting(s -> s.value())
                .contains("shop.example.com", "www.shop.example.com");
        assertThat(p.keyAlgorithm()).isEqualTo("RSA");
        assertThat(p.keySize()).isEqualTo(2048);
        assertThat(p.signatureValid()).isTrue();
    }

    @Test
    void rejectsGarbagePem() {
        assertThatThrownBy(() -> parser.parse("not a csr"))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void decodesIpSanAsDottedQuadNotHex() {
        var req = new com.example.csrgen.api.dto.CsrRequest(
                com.example.csrgen.domain.KeyAlgorithm.RSA, 2048, null,
                CryptoTestSupport.subject("ip.example.com"),
                java.util.List.of(
                        new com.example.csrgen.api.dto.SanEntryDto(
                                com.example.csrgen.domain.SanType.DNS, "ip.example.com"),
                        new com.example.csrgen.api.dto.SanEntryDto(
                                com.example.csrgen.domain.SanType.IP, "10.0.0.9")),
                null);
        GeneratedCsr g = csr.generateDetailed(req, false);
        CsrParseResponse p = parser.parse(g.csrPem());

        assertThat(p.subjectAltNames())
                .anySatisfy(s -> {
                    if (s.type() == com.example.csrgen.domain.SanType.IP) {
                        assertThat(s.value()).isEqualTo("10.0.0.9");
                    }
                });
        assertThat(p.subjectAltNames()).extracting(s -> s.value())
                .contains("10.0.0.9")
                .doesNotContain("#0a000009");
    }
}
