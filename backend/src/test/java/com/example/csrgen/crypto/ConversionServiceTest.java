package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.ConvertRequest;
import com.example.csrgen.api.dto.ConvertResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConversionServiceTest {

    private final CsrService csr = CryptoTestSupport.csrService();
    private final ConversionService conv = new ConversionService();

    @Test
    void pemToDerToPemRoundTrip() {
        GeneratedCsr g = csr.generateDetailed(CryptoTestSupport.rsaRequest("rt.com"), false);

        ConvertResponse der = conv.convert(new ConvertRequest(
                ConvertRequest.Format.PEM, ConvertRequest.Format.DER, g.csrPem(), null, null));
        assertThat(der.derBase64()).isNotBlank();

        ConvertResponse pem = conv.convert(new ConvertRequest(
                ConvertRequest.Format.DER, ConvertRequest.Format.PEM, null,
                der.derBase64(), "CERTIFICATE REQUEST"));
        assertThat(pem.pem()).contains("BEGIN CERTIFICATE REQUEST");

        // re-parse the round-tripped CSR to prove it survived intact
        assertThat(new CsrParser().parse(pem.pem()).signatureValid()).isTrue();
    }
}
