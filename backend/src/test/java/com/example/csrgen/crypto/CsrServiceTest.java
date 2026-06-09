package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CsrServiceTest {

    private final CsrService csr = CryptoTestSupport.csrService();
    private final CsrParser parser = new CsrParser();

    @Test
    void generatesValidRsaCsr() {
        CsrResponse r = csr.generate(CryptoTestSupport.rsaRequest("example.com"));
        assertThat(r.csrPem()).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(r.privateKeyPem()).contains("BEGIN PRIVATE KEY");
        assertThat(r.signatureAlgorithm()).isEqualTo("SHA256withRSA");

        var parsed = parser.parse(r.csrPem());
        assertThat(parsed.signatureValid()).isTrue();
        assertThat(parsed.subjectFields()).containsEntry("commonName", "example.com");
        assertThat(parsed.subjectAltNames()).hasSize(2);
    }

    @Test
    void detailedPkcs8EmitsPkcs8PrivateKey() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("a.com"), false);
        assertThat(g.keyPem()).contains("-----BEGIN PRIVATE KEY-----");
        assertThat(g.keyPem()).doesNotContain("RSA PRIVATE KEY");
    }

    @Test
    void detailedPkcs1EmitsTraditionalRsaKey() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("a.com"), true);
        assertThat(g.keyPem()).contains("-----BEGIN RSA PRIVATE KEY-----");
    }

    @Test
    void ecdsaIgnoresPkcs1FlagAndStaysPkcs8() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.ecRequest("ec.com", "P-256"), true);
        assertThat(g.keyPem()).contains("-----BEGIN PRIVATE KEY-----");
        assertThat(g.signatureAlgorithm()).isEqualTo("SHA256withECDSA");
        assertThat(parser.parse(g.csrPem()).signatureValid()).isTrue();
    }

    @Test
    void ecP384ProducesValidCsr() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.ecRequest("ec.com", "P-384"), false);
        var parsed = parser.parse(g.csrPem());
        assertThat(parsed.signatureValid()).isTrue();
        assertThat(parsed.keyAlgorithm()).isEqualTo("EC");
        assertThat(parsed.keySize()).isEqualTo(384);
    }
}
