package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.KeyConvertRequest;
import com.example.csrgen.contract.dto.KeyConvertResponse;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The converter matrix: every key algorithm through every representation,
 * with roundtrips (output fed back in must describe the same key).
 */
class KeyConvertServiceTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPairService keys = new KeyPairService();
    private final KeyConvertService convert = new KeyConvertService();

    private KeyConvertResponse run(String input) {
        return convert.convert(new KeyConvertRequest(input));
    }

    private KeyPair generate(String algo, String param) {
        return switch (algo) {
            case "RSA" -> keys.generate(KeyAlgorithm.RSA, Integer.parseInt(param), null);
            case "EC" -> keys.generate(KeyAlgorithm.EC, null, param);
            case "ED25519" -> keys.generate(KeyAlgorithm.ED25519, null, null);
            default -> keys.generate(KeyAlgorithm.ML_DSA, null, param); // param is the full PQC name
        };
    }

    /* ---------------- the matrix ---------------- */

    static Stream<org.junit.jupiter.params.provider.Arguments> allKeys() {
        return Stream.of(
                org.junit.jupiter.params.provider.Arguments.of("RSA", "2048", "RSA", "2048-bit", false),
                org.junit.jupiter.params.provider.Arguments.of("RSA", "3072", "RSA", "3072-bit", false),
                org.junit.jupiter.params.provider.Arguments.of("RSA", "4096", "RSA", "4096-bit", false),
                org.junit.jupiter.params.provider.Arguments.of("EC", "P-256", "EC", "P-256", false),
                org.junit.jupiter.params.provider.Arguments.of("EC", "P-384", "EC", "P-384", false),
                org.junit.jupiter.params.provider.Arguments.of("EC", "P-521", "EC", "P-521", false),
                org.junit.jupiter.params.provider.Arguments.of("ED25519", "-", "ED25519", "Ed25519", false),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "ML-DSA-44", "ML-DSA", "ML-DSA-44", true),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "ML-DSA-65", "ML-DSA", "ML-DSA-65", true),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "ML-DSA-87", "ML-DSA", "ML-DSA-87", true),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "SLH-DSA-SHA2-128S", "SLH-DSA", "SLH-DSA-SHA2-128S", true),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "FALCON-512", "Falcon", "FALCON-512", true),
                org.junit.jupiter.params.provider.Arguments.of("PQC", "FALCON-1024", "Falcon", "FALCON-1024", true));
    }

    @ParameterizedTest(name = "[{index}] {0} {1} private key → all formats")
    @MethodSource("allKeys")
    void privateKeyAllFormats(String algo, String param, String kind, String detail, boolean pqc) {
        KeyPair kp = generate(algo, param);
        String pkcs8 = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        KeyConvertResponse r = run(pkcs8);

        assertThat(r.inputType()).isEqualTo("private-key");
        assertThat(r.keyKind()).isEqualTo(kind);
        assertThat(r.keyDetail()).isEqualToIgnoringCase(detail);
        assertThat(r.pqc()).isEqualTo(pqc);

        // private forms
        assertThat(r.pkcs8Pem()).contains("BEGIN PRIVATE KEY");
        assertThat(Base64.getDecoder().decode(r.pkcs8DerBase64()))
                .isEqualTo(kp.getPrivate().getEncoded());
        if (kind.equals("RSA")) {
            assertThat(r.traditionalPem()).contains("BEGIN RSA PRIVATE KEY");
        } else if (kind.equals("EC")) {
            assertThat(r.traditionalPem()).contains("BEGIN EC PRIVATE KEY");
        } else {
            assertThat(r.traditionalPem()).isNull();
        }

        // public forms — derived public key must equal the generated one
        assertThat(r.publicPem()).contains("BEGIN PUBLIC KEY");
        assertThat(Base64.getDecoder().decode(r.publicDerBase64()))
                .isEqualTo(kp.getPublic().getEncoded());
        assertThat(r.spkiSha256()).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
        assertThat(r.spkiPin()).isNotBlank();

        if (pqc) {
            assertThat(r.jwk()).isNull();
            assertThat(r.sshPublicKey()).isNull();
            assertThat(r.warnings()).anySatisfy(w -> assertThat(w).containsIgnoringCase("JWK"));
        } else {
            assertThat(r.jwk()).isNotNull();
            assertThat(r.sshPublicKey()).isNotBlank();
            assertThat(r.sshFingerprint()).startsWith("SHA256:");
        }
    }

    @ParameterizedTest(name = "[{index}] {0} {1} PKCS#8 → traditional → same key")
    @CsvSource({"RSA,2048", "EC,P-256", "EC,P-384", "EC,P-521"})
    void traditionalRoundtrip(String algo, String param) {
        KeyPair kp = generate(algo, param);
        KeyConvertResponse first = run(PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        KeyConvertResponse second = run(first.traditionalPem());
        assertThat(second.inputType()).isEqualTo("private-key");
        assertThat(second.publicPem()).isEqualTo(first.publicPem());
        assertThat(second.pkcs8Pem()).isEqualTo(first.pkcs8Pem());
        assertThat(second.spkiSha256()).isEqualTo(first.spkiSha256());
    }

    @ParameterizedTest(name = "[{index}] {0} {1} public-key input")
    @MethodSource("allKeys")
    void publicKeyInput(String algo, String param, String kind, String detail, boolean pqc) {
        KeyPair kp = generate(algo, param);
        KeyConvertResponse r = run(PemUtil.toPem("PUBLIC KEY", kp.getPublic().getEncoded()));
        assertThat(r.inputType()).isEqualTo("public-key");
        assertThat(r.keyKind()).isEqualTo(kind);
        assertThat(r.pkcs8Pem()).isNull();
        assertThat(r.traditionalPem()).isNull();
        assertThat(Base64.getDecoder().decode(r.publicDerBase64()))
                .isEqualTo(kp.getPublic().getEncoded());
    }

    @ParameterizedTest(name = "[{index}] {0} {1} bare-base64 private key")
    @CsvSource({"RSA,2048", "EC,P-256", "ED25519,-", "PQC,ML-DSA-65"})
    void bareBase64PrivateKey(String algo, String param) {
        KeyPair kp = generate(algo, param);
        String bare = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        KeyConvertResponse r = run(bare);
        assertThat(r.inputType()).isEqualTo("private-key");
        assertThat(Base64.getDecoder().decode(r.publicDerBase64()))
                .isEqualTo(kp.getPublic().getEncoded());
    }

    /* ---------------- JWK correctness ---------------- */

    @Test
    void rsaJwkCarriesTheRealModulusAndExponent() {
        KeyPair kp = generate("RSA", "2048");
        KeyConvertResponse r = run(PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        assertThat(r.jwk().get("kty")).isEqualTo("RSA");
        assertThat(new BigInteger(1, Base64.getUrlDecoder().decode(r.jwk().get("n"))))
                .isEqualTo(pub.getModulus());
        assertThat(new BigInteger(1, Base64.getUrlDecoder().decode(r.jwk().get("e"))))
                .isEqualTo(pub.getPublicExponent());
    }

    @ParameterizedTest(name = "[{index}] EC {0} JWK crv + coordinate length")
    @CsvSource({"P-256,32", "P-384,48", "P-521,66"})
    void ecJwkCurveAndCoordinates(String curve, int flen) {
        KeyPair kp = generate("EC", curve);
        KeyConvertResponse r = run(PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        assertThat(r.jwk().get("kty")).isEqualTo("EC");
        assertThat(r.jwk().get("crv")).isEqualTo(curve);
        assertThat(Base64.getUrlDecoder().decode(r.jwk().get("x"))).hasSize(flen);
        assertThat(Base64.getUrlDecoder().decode(r.jwk().get("y"))).hasSize(flen);
    }

    @Test
    void ed25519JwkIsOkpWithRawPoint() {
        KeyPair kp = generate("ED25519", "-");
        KeyConvertResponse r = run(PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        assertThat(r.jwk().get("kty")).isEqualTo("OKP");
        assertThat(r.jwk().get("crv")).isEqualTo("Ed25519");
        assertThat(Base64.getUrlDecoder().decode(r.jwk().get("x"))).hasSize(32);
    }

    /* ---------------- OpenSSH format ---------------- */

    @ParameterizedTest(name = "[{index}] {0} {1} SSH prefix {2}")
    @CsvSource({"RSA,2048,ssh-rsa", "EC,P-256,ecdsa-sha2-nistp256",
            "EC,P-384,ecdsa-sha2-nistp384", "EC,P-521,ecdsa-sha2-nistp521",
            "ED25519,-,ssh-ed25519"})
    void sshLineHasTheRightAlgoInsideAndOut(String algo, String param, String prefix) {
        KeyPair kp = generate(algo, param);
        KeyConvertResponse r = run(PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        String[] parts = r.sshPublicKey().split(" ");
        assertThat(parts[0]).isEqualTo(prefix);
        // wire format: first field of the blob is the algorithm name again
        byte[] blob = Base64.getDecoder().decode(parts[1]);
        int len = ((blob[0] & 0xFF) << 24) | ((blob[1] & 0xFF) << 16)
                | ((blob[2] & 0xFF) << 8) | (blob[3] & 0xFF);
        assertThat(new String(blob, 4, len)).isEqualTo(prefix);
    }

    /* ---------------- cert / CSR input ---------------- */

    @Test
    void certificateInputExtractsThePublicKey() {
        var g = CryptoTestSupport.csrService()
                .generateDetailed(CryptoTestSupport.rsaRequest("convert.example.com"), false);
        var cert = new CertService(new CsrParser(), new ConversionService());
        String certPem = cert.selfSign(g.csrPem(), g.keyPem(), 30);
        KeyConvertResponse r = run(certPem);
        assertThat(r.inputType()).isEqualTo("certificate");
        assertThat(r.keyKind()).isEqualTo("RSA");
        assertThat(r.publicPem()).contains("BEGIN PUBLIC KEY");
        assertThat(r.pkcs8Pem()).isNull();
    }

    @Test
    void csrInputExtractsThePublicKey() {
        var g = CryptoTestSupport.csrService()
                .generateDetailed(CryptoTestSupport.ecRequest("csr.example.com", "P-256"), false);
        KeyConvertResponse r = run(g.csrPem());
        assertThat(r.inputType()).isEqualTo("csr");
        assertThat(r.keyKind()).isEqualTo("EC");
        assertThat(r.keyDetail()).isEqualTo("P-256");
        assertThat(r.jwk()).containsEntry("crv", "P-256");
    }

    /* ---------------- errors ---------------- */

    @Test
    void emptyInputIsRejectedKindly() {
        assertThatThrownBy(() -> run("  "))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Paste a key");
    }

    @Test
    void garbageIsRejectedKindly() {
        assertThatThrownBy(() -> run("not a key at all !!!"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("isn't PEM or valid base64");
    }

    @Test
    void randomBase64IsRejectedKindly() {
        String junk = Base64.getEncoder().encodeToString("random bytes, not DER".getBytes());
        assertThatThrownBy(() -> run(junk))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("isn't a key, certificate or CSR");
    }

    @Test
    void encryptedKeyGetsAHelpfulMessage() {
        String enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----";
        assertThatThrownBy(() -> run(enc))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("encrypted");
    }
}
