package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.ContractKey;
import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.ContractSubject;
import com.example.csrgen.contract.dto.DecodeResponse;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.contract.dto.MatchResponse;
import com.example.csrgen.crypto.ConversionService;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.KeyPairService;
import com.example.csrgen.crypto.MatchService;
import com.example.csrgen.crypto.ValidationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.List;

import com.example.csrgen.contract.dto.GenerateRequest.Extensions;
import com.example.csrgen.crypto.CryptoException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContractServiceTest {

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final CsrParser parser = new CsrParser();
    private final CsrService csrService =
            new CsrService(new KeyPairService(), new ValidationService());
    private final ConversionService conversion = new ConversionService();
    private final ContractService contract = new ContractService(
            csrService, parser, new MatchService(parser, conversion),
            new com.example.csrgen.crypto.CertService(parser, conversion), new RecordService(null));

    private ContractSubject subject(String cn) {
        return new ContractSubject(cn, "Example Inc.", "IT", "San Francisco", "California", "US", "a@b.com");
    }

    @Test
    void generateRsaPkcs8() {
        GenerateRequest req = new GenerateRequest(subject("shop.example.com"),
                List.of(new ContractSan("DNS", "shop.example.com"), new ContractSan("IP", "203.0.113.10")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256");
        GenerateResponse r = contract.generate(req);

        assertThat(r.csr()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(r.privateKey()).contains("BEGIN PRIVATE KEY");
        assertThat(r.details().keyLabel()).isEqualTo("RSA 2048");
        assertThat(r.details().keyDetail()).isEqualTo("2048-bit");
        assertThat(r.details().keyFormat()).isEqualTo("PKCS#8");
        assertThat(r.details().signatureAlgorithm()).isEqualTo("SHA-256");
    }

    @Test
    void generateRsaPkcs1() {
        GenerateRequest req = new GenerateRequest(subject("a.com"), List.of(),
                new ContractKey("RSA", 3072, null, "PKCS#1"), "SHA-384");
        GenerateResponse r = contract.generate(req);
        assertThat(r.privateKey()).contains("BEGIN RSA PRIVATE KEY");
        assertThat(r.details().keyFormat()).isEqualTo("PKCS#1");
        assertThat(r.details().keyLabel()).isEqualTo("RSA 3072");
    }

    @Test
    void generateEcdsa() {
        GenerateRequest req = new GenerateRequest(subject("ec.com"), List.of(),
                new ContractKey("ECDSA", null, "P-256", "PKCS#8"), "SHA-256");
        GenerateResponse r = contract.generate(req);
        assertThat(r.details().keyLabel()).isEqualTo("ECDSA P-256");
        assertThat(r.details().keyFormat()).isEqualTo("PKCS#8");
        assertThat(r.privateKey()).contains("BEGIN PRIVATE KEY");
    }

    @Test
    void decodeRoundTrip() {
        GenerateRequest req = new GenerateRequest(subject("dec.example.com"),
                List.of(new ContractSan("DNS", "dec.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256");
        GenerateResponse gen = contract.generate(req);

        DecodeResponse d = contract.decode(gen.csr());
        assertThat(d.subject().commonName()).isEqualTo("dec.example.com");
        assertThat(d.subject().country()).isEqualTo("US");
        assertThat(d.key().kind()).isEqualTo("RSA");
        assertThat(d.key().bits()).isEqualTo(2048);
        assertThat(d.signature().valid()).isTrue();
        assertThat(d.subjectAltNames()).extracting(ContractSan::value).contains("dec.example.com");
    }

    @Test
    void decodeEcReportsEcdsaKind() {
        GenerateResponse gen = contract.generate(new GenerateRequest(subject("ec.com"), List.of(),
                new ContractKey("ECDSA", null, "P-384", "PKCS#8"), "SHA-384"));
        DecodeResponse d = contract.decode(gen.csr());
        assertThat(d.key().kind()).isEqualTo("ECDSA");
        assertThat(d.key().detail()).isEqualTo("P-384");
    }

    @Test
    void emailAddedAsRfc822San() {
        GenerateResponse g = contract.generate(new GenerateRequest(
                new ContractSubject("e.example.com", null, null, null, null, "US", "admin@example.com"),
                List.of(), new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.subjectAltNames()).extracting(ContractSan::value).contains("admin@example.com");
    }

    @Test
    void signatureAlgorithmPretty() {
        GenerateResponse g = contract.generate(new GenerateRequest(subject("p.com"), List.of(),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        assertThat(contract.decode(g.csr()).signature().algorithm()).contains("withRSA");
    }

    @Test
    void generateWithKeyUsageAndEku() {
        Extensions ext = new Extensions(List.of("digitalSignature", "keyEncipherment"), List.of("serverAuth", "clientAuth"));
        GenerateResponse g = contract.generate(new GenerateRequest(subject("x.com"),
                List.of(new ContractSan("DNS", "x.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256", ext));
        assertThat(g.csr()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(parser.parse(g.csr()).signatureValid()).isTrue();
    }

    @Test
    void unknownKeyUsageRejected() {
        Extensions ext = new Extensions(List.of("bogusUsage"), null);
        assertThatThrownBy(() -> contract.generate(new GenerateRequest(subject("x.com"), List.of(),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256", ext)))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void generateEd25519() {
        GenerateResponse g = contract.generate(new GenerateRequest(subject("ed.example.com"),
                List.of(new ContractSan("DNS", "ed.example.com")),
                new ContractKey("Ed25519", null, null, "PKCS#8"), "SHA-256"));
        assertThat(g.details().keyLabel()).isEqualTo("Ed25519");
        assertThat(g.privateKey()).contains("BEGIN PRIVATE KEY");
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.key().kind()).isEqualTo("Ed25519");
        assertThat(d.signature().valid()).isTrue();
    }

    @Test
    void decodeShowsRequestedExtensions() {
        Extensions ext = new Extensions(List.of("digitalSignature", "keyEncipherment"), List.of("serverAuth"));
        GenerateResponse g = contract.generate(new GenerateRequest(subject("x.com"),
                List.of(new ContractSan("DNS", "x.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256", ext));
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.extensions()).isNotNull();
        assertThat(d.extensions().keyUsage()).contains("digitalSignature", "keyEncipherment");
        assertThat(d.extensions().extendedKeyUsage()).contains("serverAuth");
    }

    @Test
    void sanOnlyCsrAllowedWhenCnEmpty() {
        GenerateResponse g = contract.generate(new GenerateRequest(
                new ContractSubject(null, null, null, null, null, null, null),
                List.of(new ContractSan("DNS", "sanonly.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        assertThat(contract.decode(g.csr()).subjectAltNames())
                .extracting(ContractSan::value).contains("sanonly.example.com");
    }

    @Test
    void noCnAndNoSanRejected() {
        assertThatThrownBy(() -> contract.generate(new GenerateRequest(
                new ContractSubject(null, null, null, null, null, null, null),
                List.of(), new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256")))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void countryUppercased() {
        GenerateResponse g = contract.generate(new GenerateRequest(
                new ContractSubject("c.com", null, null, null, null, "us", null),
                List.of(new ContractSan("DNS", "c.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        assertThat(contract.decode(g.csr()).subject().country()).isEqualTo("US");
    }

    @Test
    void basicConstraintsRequestedAndDecoded() {
        Extensions ext = new Extensions(List.of("keyCertSign"), null, true, 1);
        GenerateResponse g = contract.generate(new GenerateRequest(subject("ca.example.com"),
                List.of(new ContractSan("DNS", "ca.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256", ext));
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.extensions().basicConstraints()).contains("CA:TRUE");
    }

    @Test
    void rsaPssSignature() {
        GenerateResponse g = contract.generate(new GenerateRequest(subject("pss.example.com"),
                List.of(new ContractSan("DNS", "pss.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8", true), "SHA-256"));
        assertThat(g.details().signatureAlgorithm()).contains("PSS");
        assertThat(parser.parse(g.csr()).signatureValid()).isTrue();
    }

    @Test
    void selfSignedCertificateFromCsr() throws Exception {
        var r = contract.selfSigned(new GenerateRequest(subject("self.example.com"),
                List.of(new ContractSan("DNS", "self.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"), 365);
        assertThat(r.certificate()).contains("BEGIN CERTIFICATE");
        assertThat(r.csr()).contains("BEGIN CERTIFICATE REQUEST");

        var cf = java.security.cert.CertificateFactory.getInstance("X.509",
                org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
        var cert = (java.security.cert.X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(r.certificate().getBytes()));
        assertThat(cert.getSubjectX500Principal().getName()).contains("self.example.com");
        cert.checkValidity(); // not expired
    }

    @Test
    void decodeIncludesPublicKeyFingerprint() {
        GenerateResponse g = contract.generate(new GenerateRequest(subject("fp.example.com"),
                List.of(new ContractSan("DNS", "fp.example.com")),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        DecodeResponse d = contract.decode(g.csr());
        assertThat(d.key().sha256()).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
        assertThat(d.key().pin()).isNotBlank();
    }

    @Test
    void matchTrueForOwnKey() {
        GenerateResponse gen = contract.generate(new GenerateRequest(subject("m.com"), List.of(),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256"));
        MatchResponse m = contract.match(gen.csr(), gen.privateKey());
        assertThat(m.supported()).isTrue();
        assertThat(m.match()).isTrue();
        assertThat(m.bits()).isEqualTo(2048);
    }
}
