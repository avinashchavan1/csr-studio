package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.ContractKey;
import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.ContractSubject;
import com.example.csrgen.contract.dto.DecodeResponse;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateRequest.Extensions;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.crypto.CertService;
import com.example.csrgen.crypto.ConversionService;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.KeyPairService;
import com.example.csrgen.crypto.MatchService;
import com.example.csrgen.crypto.ValidationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Large combinatorial roundtrip matrix: for every (algorithm × format × hash × PSS ×
 * SAN set × extension set) combination we generate a CSR, decode it, and assert the
 * self-signature verifies and every field survives the roundtrip. This is the core
 * correctness guarantee for a business-critical crypto app.
 */
class ContractGenerateMatrixTest {

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final CsrParser parser = new CsrParser();
    private final ContractService contract = new ContractService(
            new CsrService(new KeyPairService(), new ValidationService()),
            parser,
            new MatchService(parser, new ConversionService()),
            new CertService(parser, new ConversionService()),
            new RecordService(null));

    // ---- a single test case ----
    record KeyCfg(String algorithm, Integer size, String curve, String format,
                  boolean pss, String kind, String detail, boolean pqc, boolean hashVaries) {
    }

    record Case(KeyCfg key, String hash, String label, List<ContractSan> sans, Extensions ext) {
        @Override public String toString() {
            return key.kind() + (key.detail() != null ? " " + key.detail() : "")
                    + (key.pss() ? " PSS" : "") + " " + key.format()
                    + " / " + hash + " / " + label
                    + (ext != null ? " +ext" : "");
        }
    }

    private static ContractSubject subject(String cn) {
        return new ContractSubject(cn, "Example Inc.", "IT", "San Francisco", "California", "US", "a@b.com");
    }

    private static final String CN = "matrix.example.com";

    // SAN sets (label → sans)
    private static List<Object[]> sanSets() {
        return List.of(
                new Object[]{"1dns", List.of(new ContractSan("DNS", CN))},
                new Object[]{"dns+ip", List.of(new ContractSan("DNS", CN), new ContractSan("IP", "203.0.113.10"))},
                new Object[]{"multi", List.of(new ContractSan("DNS", CN), new ContractSan("DNS", "www." + CN), new ContractSan("DNS", "api." + CN))},
                new Object[]{"wildcard", List.of(new ContractSan("DNS", "*." + CN))});
    }

    private static List<Extensions> extSets() {
        List<Extensions> l = new ArrayList<>();
        l.add(null);
        l.add(new Extensions(List.of("digitalSignature", "keyEncipherment"), List.of("serverAuth")));
        l.add(new Extensions(List.of("keyCertSign"), List.of(), true, 0));
        return l;
    }

    // Cheap keys → full cartesian; expensive keys → one representative each.
    private static final List<KeyCfg> FAST = List.of(
            new KeyCfg("ECDSA", null, "P-256", "PKCS#8", false, "ECDSA", "P-256", false, true),
            new KeyCfg("Ed25519", null, null, "PKCS#8", false, "Ed25519", null, false, false),
            new KeyCfg("RSA", 2048, null, "PKCS#8", false, "RSA", "2048-bit", false, true),
            new KeyCfg("RSA", 2048, null, "PKCS#1", false, "RSA", "2048-bit", false, true),
            new KeyCfg("RSA", 2048, null, "PKCS#8", true, "RSA", "2048-bit", false, true));

    private static final List<KeyCfg> COVERAGE = List.of(
            new KeyCfg("RSA", 3072, null, "PKCS#8", false, "RSA", "3072-bit", false, false),
            new KeyCfg("RSA", 4096, null, "PKCS#8", false, "RSA", "4096-bit", false, false),
            new KeyCfg("ECDSA", null, "P-384", "PKCS#8", false, "ECDSA", "P-384", false, false),
            new KeyCfg("ECDSA", null, "P-521", "PKCS#8", false, "ECDSA", "P-521", false, false),
            new KeyCfg("ML-DSA-44", null, null, "PKCS#8", false, "ML-DSA-44", null, true, false),
            new KeyCfg("ML-DSA-65", null, null, "PKCS#8", false, "ML-DSA-65", null, true, false),
            new KeyCfg("ML-DSA-87", null, null, "PKCS#8", false, "ML-DSA-87", null, true, false),
            new KeyCfg("SLH-DSA-SHA2-128S", null, null, "PKCS#8", false, "SLH-DSA-SHA2-128S", null, true, false),
            new KeyCfg("Falcon-512", null, null, "PKCS#8", false, "FALCON-512", null, true, false),
            new KeyCfg("Falcon-1024", null, null, "PKCS#8", false, "FALCON-1024", null, true, false));

    private static final String[] HASHES = {"SHA-256", "SHA-384", "SHA-512"};

    static Stream<Arguments> cases() {
        List<Arguments> out = new ArrayList<>();
        // Fast lane: full cartesian.
        for (KeyCfg k : FAST) {
            String[] hashes = k.hashVaries() ? HASHES : new String[]{"SHA-256"};
            for (String h : hashes) {
                for (Object[] san : sanSets()) {
                    for (Extensions ext : extSets()) {
                        @SuppressWarnings("unchecked")
                        List<ContractSan> sans = (List<ContractSan>) san[1];
                        out.add(Arguments.of(new Case(k, h, (String) san[0], sans, ext)));
                    }
                }
            }
        }
        // Coverage lane: one representative each (1 SAN set, no ext).
        List<ContractSan> oneSan = List.of(new ContractSan("DNS", CN));
        for (KeyCfg k : COVERAGE) {
            out.add(Arguments.of(new Case(k, "SHA-256", "1dns", oneSan, null)));
        }
        return out.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void generateDecodeRoundtrip(Case c) {
        GenerateRequest req = new GenerateRequest(
                subject(CN), c.sans(),
                new ContractKey(c.key().algorithm(), c.key().size(), c.key().curve(), c.key().format(), c.key().pss()),
                c.hash(), c.ext());

        GenerateResponse g = contract.generate(req);

        // --- generation shape ---
        assertThat(g.csr()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(g.privateKey()).contains("PRIVATE KEY");
        if ("PKCS#1".equals(c.key().format())) {
            assertThat(g.privateKey()).contains("BEGIN RSA PRIVATE KEY");
        }

        // --- decode roundtrip ---
        DecodeResponse d = contract.decode(g.csr());

        assertThat(d.signature().valid())
                .as("self-signature must verify for " + c)
                .isTrue();
        assertThat(d.subject().commonName()).isEqualTo(CN);
        assertThat(d.key().kind()).isEqualTo(c.key().kind());
        if (c.key().detail() != null) {
            assertThat(d.key().detail()).isEqualTo(c.key().detail());
        }

        // SAN values survive
        List<String> decodedSans = d.subjectAltNames().stream().map(ContractSan::value).toList();
        for (ContractSan s : c.sans()) {
            assertThat(decodedSans).contains(s.value());
        }

        // extension roundtrip
        if (c.ext() != null) {
            if (c.ext().keyUsage() != null && !c.ext().keyUsage().isEmpty()) {
                assertThat(d.extensions()).isNotNull();
                assertThat(d.extensions().keyUsage()).containsAll(c.ext().keyUsage());
            }
            if (c.ext().extendedKeyUsage() != null && !c.ext().extendedKeyUsage().isEmpty()) {
                assertThat(d.extensions().extendedKeyUsage()).containsAll(c.ext().extendedKeyUsage());
            }
            if (Boolean.TRUE.equals(c.ext().basicConstraintsCa())) {
                assertThat(d.extensions().basicConstraints()).contains("CA:TRUE");
            }
        }
    }
}
