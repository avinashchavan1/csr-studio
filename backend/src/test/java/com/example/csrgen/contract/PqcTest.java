package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.ContractKey;
import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.ContractSubject;
import com.example.csrgen.contract.dto.DecodeResponse;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.crypto.CertService;
import com.example.csrgen.crypto.ConversionService;
import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.KeyPairService;
import com.example.csrgen.crypto.MatchService;
import com.example.csrgen.crypto.ValidationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Security;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Post-quantum (PQC) signature algorithms: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon. */
class PqcTest {

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final CsrParser parser = new CsrParser();
    private final ConversionService conversion = new ConversionService();
    private final CsrService csrService = new CsrService(new KeyPairService(), new ValidationService());
    private final ContractService contract = new ContractService(
            csrService, parser, new MatchService(parser, conversion),
            new CertService(parser, conversion));

    private GenerateRequest req(String algo) {
        return new GenerateRequest(
                new ContractSubject("pqc.example.com", "Acme", null, null, null, "US", null),
                List.of(new ContractSan("DNS", "pqc.example.com")),
                new ContractKey(algo, null, null, "PKCS#8"), "SHA-256");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024", "SLH-DSA-SHA2-128S"})
    void generatesValidPqcCsr(String algo) {
        GenerateResponse g = contract.generate(req(algo));
        assertThat(g.csr()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(g.privateKey()).contains("BEGIN PRIVATE KEY");
        assertThat(g.details().keyFormat()).isEqualTo("PKCS#8");
        // the CSR's self-signature must verify with the PQC public key
        assertThat(parser.parse(g.csr()).signatureValid()).isTrue();
    }

    @Test
    void decodeReportsPqcKeyKind() {
        GenerateResponse g = contract.generate(req("ML-DSA-65"));
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.key().kind()).isEqualTo("ML-DSA-65");
        assertThat(d.key().detail()).contains("FIPS 204");
        assertThat(d.signature().valid()).isTrue();
        assertThat(d.signature().algorithm()).containsIgnoringCase("ML-DSA-65");
    }

    @Test
    void selfSignedPqcCertificate() throws Exception {
        var r = contract.selfSigned(req("ML-DSA-65"), 365);
        assertThat(r.certificate()).contains("BEGIN CERTIFICATE");
        var cf = java.security.cert.CertificateFactory.getInstance("X.509", "BC");
        var cert = (java.security.cert.X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(r.certificate().getBytes()));
        assertThat(cert.getPublicKey().getAlgorithm()).containsIgnoringCase("ML-DSA");
        cert.checkValidity();
    }

    @Test
    void unknownPqcParameterSetRejected() {
        assertThatThrownBy(() -> contract.generate(req("ML-DSA-99")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Unsupported key algorithm");
    }

    @Test
    void pqcKeyMatchReportsUnsupported() {
        GenerateResponse g = contract.generate(req("ML-DSA-65"));
        var m = contract.match(g.csr(), g.privateKey());
        assertThat(m.supported()).isFalse();   // match is RSA-only
    }
}
