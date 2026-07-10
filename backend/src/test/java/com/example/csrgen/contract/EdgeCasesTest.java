package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.ContractKey;
import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.ContractSubject;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.VerifyRequest;
import com.example.csrgen.crypto.CertService;
import com.example.csrgen.crypto.ConversionService;
import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.KeyPairService;
import com.example.csrgen.crypto.MatchService;
import com.example.csrgen.crypto.ValidationService;
import com.example.csrgen.crypto.VerifyService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Security;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Negative / edge-case matrix — malformed input, wrong objects, bad parameters.
 * Every one must fail with a clear, actionable message (never a raw stack trace).
 */
class EdgeCasesTest {

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
    private final VerifyService verify = new VerifyService();

    private static ContractSubject subj(String cn) {
        return new ContractSubject(cn, "O", null, null, null, "US", null);
    }

    /* ---------------- decode: wrong object / malformed ---------------- */

    static Stream<Arguments> badDecodeInputs() {
        return Stream.of(
                Arguments.of("-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----", "private key"),
                Arguments.of("-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----", "certificate"),
                Arguments.of("-----BEGIN PUBLIC KEY-----\nMIIabc\n-----END PUBLIC KEY-----", "public key"),
                Arguments.of("not a csr at all !!! @@@", "base64"),
                Arguments.of("", "Nothing to decode"),
                Arguments.of("MIICbzCCAVcCAQAwKjEZ", "isn't a valid"));
    }

    @ParameterizedTest(name = "decode rejects: {1}")
    @MethodSource("badDecodeInputs")
    void decodeRejectsBadInputWithFriendlyMessage(String input, String expected) {
        assertThatThrownBy(() -> contract.decode(input))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining(expected);
    }

    /* ---------------- generate: invalid parameters ---------------- */

    @ParameterizedTest(name = "weak RSA {0} rejected")
    @CsvSource({"512", "768", "1024"})
    void weakRsaRejected(int size) {
        GenerateRequest req = new GenerateRequest(subj("a.com"),
                List.of(new ContractSan("DNS", "a.com")),
                new ContractKey("RSA", size, null, "PKCS#8"), "SHA-256");
        assertThatThrownBy(() -> contract.generate(req)).isInstanceOf(CryptoException.class);
    }

    @ParameterizedTest(name = "unknown algorithm ''{0}'' rejected")
    @CsvSource({"RSA-999", "FOO", "ML-DSA-99", "dilithium", "P-256"})
    void unknownAlgorithmRejected(String algo) {
        GenerateRequest req = new GenerateRequest(subj("a.com"),
                List.of(new ContractSan("DNS", "a.com")),
                new ContractKey(algo, 2048, null, "PKCS#8"), "SHA-256");
        assertThatThrownBy(() -> contract.generate(req)).isInstanceOf(CryptoException.class);
    }

    @org.junit.jupiter.api.Test
    void noCommonNameAndNoSanRejected() {
        GenerateRequest req = new GenerateRequest(
                new ContractSubject(null, "Org", null, null, null, "US", null),
                List.of(),
                new ContractKey("RSA", 2048, null, "PKCS#8"), "SHA-256");
        assertThatThrownBy(() -> contract.generate(req))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Common Name");
    }

    /* ---------------- verify: malformed requests ---------------- */

    private VerifyRequest v(String message, String msgEnc, String sig, String sigEnc,
                            String pub, String hash, String mode) {
        return new VerifyRequest(mode, message, msgEnc, sig, sigEnc, pub, "auto", hash, null, null, null);
    }

    @org.junit.jupiter.api.Test
    void verifyMissingVerifierRejected() {
        assertThatThrownBy(() -> verify.verify(v("hi", "utf8", "AAAA", "base64", null, null, "detached")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("public key or a certificate");
    }

    @ParameterizedTest(name = "verify bad encoding: {0}")
    @CsvSource({
            "base64,'!!!not base64!!!',base64",
            "hex,'zzzz',hex",
            "hex,'abc',hex"        // odd length hex
    })
    void verifyBadSignatureEncodingRejected(String label, String sig, String sigEnc) {
        String pub = SamplePub.RSA;
        assertThatThrownBy(() -> verify.verify(v("hi", "utf8", sig, sigEnc, pub, null, "detached")))
                .isInstanceOf(CryptoException.class);
    }

    @org.junit.jupiter.api.Test
    void verifyUnsupportedHashRejected() {
        assertThatThrownBy(() -> verify.verify(v("hi", "utf8", "AAAA", "base64", SamplePub.RSA, "MD5", "detached")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("SHA-256");
    }

    @org.junit.jupiter.api.Test
    void verifyUnknownModeRejected() {
        assertThatThrownBy(() -> verify.verify(v("hi", "utf8", "AAAA", "base64", SamplePub.RSA, null, "bogus")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("mode");
    }

    @org.junit.jupiter.api.Test
    void verifyPrivateKeyAsVerifierRejected() {
        String priv = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----";
        assertThatThrownBy(() -> verify.verify(v("hi", "utf8", "AAAA", "base64", priv, null, "detached")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("PUBLIC key");
    }

    /** A real RSA public key so bad-signature cases exercise the crypto path, not key parsing. */
    static final class SamplePub {
        static final String RSA;
        static {
            try {
                var kp = new KeyPairService().generate(com.example.csrgen.domain.KeyAlgorithm.RSA, 2048, null);
                RSA = com.example.csrgen.crypto.PemUtil.toPem(kp.getPublic());
            } catch (Exception e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }
}
