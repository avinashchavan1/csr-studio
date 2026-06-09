package com.example.csrgen.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MatchServiceTest {

    private final CsrService csr = CryptoTestSupport.csrService();
    private final MatchService match = new MatchService(new CsrParser(), new ConversionService());

    @Test
    void matchesGeneratedPair() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("m.com"), false);
        MatchService.Result r = match.match(g.csrPem(), g.keyPem());
        assertThat(r.supported()).isTrue();
        assertThat(r.match()).isTrue();
        assertThat(r.bits()).isEqualTo(2048);
    }

    @Test
    void matchesPkcs1KeyToo() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("m.com"), true);
        MatchService.Result r = match.match(g.csrPem(), g.keyPem());
        assertThat(r.supported()).isTrue();
        assertThat(r.match()).isTrue();
    }

    @Test
    void detectsMismatchedKey() {
        GeneratedCsr a = csr.generateDetailed(CryptoTestSupport.rsaRequest("a.com"), false);
        GeneratedCsr b = csr.generateDetailed(CryptoTestSupport.rsaRequest("b.com"), false);
        MatchService.Result r = match.match(a.csrPem(), b.keyPem());
        assertThat(r.supported()).isTrue();
        assertThat(r.match()).isFalse();
    }

    @Test
    void reportsUnsupportedForEcCsr() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.ecRequest("ec.com", "P-256"), false);
        MatchService.Result r = match.match(g.csrPem(), g.keyPem());
        assertThat(r.supported()).isFalse();
    }
}
