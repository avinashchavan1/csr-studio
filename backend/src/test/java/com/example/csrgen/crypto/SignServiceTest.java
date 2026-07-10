package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.SignRequest;
import com.example.csrgen.contract.dto.SignResponse;
import com.example.csrgen.contract.dto.VerifyRequest;
import com.example.csrgen.contract.dto.VerifyResponse;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.KeyPair;
import java.security.Security;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Sign → verify round-trip across every algorithm. Proves the /csr/sign endpoint
 * produces a signature that /csr/verify accepts, and that the public key derived
 * from the private key is correct. This closes the sign/verify loop.
 */
class SignServiceTest {

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPairService keys = new KeyPairService();
    private final SignService sign = new SignService();
    private final VerifyService verify = new VerifyService();

    private static final String MSG = "sign-verify round trip ✓ αβγ 42";

    record Cfg(String label, KeyAlgorithm alg, Integer rsa, String param,
               String hash, boolean pss, String kind, boolean pqc) {
        @Override public String toString() { return label; }
    }

    static Stream<Arguments> configs() {
        return Stream.of(
                new Cfg("RSA/SHA-256", KeyAlgorithm.RSA, 2048, null, "SHA-256", false, "RSA", false),
                new Cfg("RSA/SHA-384", KeyAlgorithm.RSA, 2048, null, "SHA-384", false, "RSA", false),
                new Cfg("RSA/SHA-512", KeyAlgorithm.RSA, 2048, null, "SHA-512", false, "RSA", false),
                new Cfg("RSA-PSS/SHA-256", KeyAlgorithm.RSA, 2048, null, "SHA-256", true, "RSA", false),
                new Cfg("EC P-256", KeyAlgorithm.EC, null, "P-256", "SHA-256", false, "EC", false),
                new Cfg("EC P-384", KeyAlgorithm.EC, null, "P-384", "SHA-384", false, "EC", false),
                new Cfg("EC P-521", KeyAlgorithm.EC, null, "P-521", "SHA-512", false, "EC", false),
                new Cfg("Ed25519", KeyAlgorithm.ED25519, null, null, "SHA-256", false, "ED25519", false),
                new Cfg("ML-DSA-44", KeyAlgorithm.ML_DSA, null, "ML-DSA-44", "SHA-256", false, "ML-DSA", true),
                new Cfg("ML-DSA-65", KeyAlgorithm.ML_DSA, null, "ML-DSA-65", "SHA-256", false, "ML-DSA", true),
                new Cfg("ML-DSA-87", KeyAlgorithm.ML_DSA, null, "ML-DSA-87", "SHA-256", false, "ML-DSA", true),
                new Cfg("SLH-DSA", KeyAlgorithm.SLH_DSA, null, "SLH-DSA-SHA2-128S", "SHA-256", false, "SLH-DSA", true),
                new Cfg("Falcon-512", KeyAlgorithm.FALCON, null, "Falcon-512", "SHA-256", false, "Falcon", true),
                new Cfg("Falcon-1024", KeyAlgorithm.FALCON, null, "Falcon-1024", "SHA-256", false, "Falcon", true)
        ).map(Arguments::of);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("configs")
    void signThenVerifyRoundtrip(Cfg c) {
        KeyPair kp = keys.generate(c.alg(), c.rsa(), c.param());
        String privPem = PemUtil.toPem(kp.getPrivate());

        SignResponse s = sign.sign(new SignRequest(MSG, "utf8", privPem, "auto", c.hash(), c.pss()));
        assertThat(s.signature()).isNotBlank();
        assertThat(s.signatureHex()).isNotBlank();
        assertThat(s.keyKind()).isEqualTo(c.kind());
        assertThat(s.pqc()).isEqualTo(c.pqc());
        assertThat(s.publicKey()).as("public key must be derivable for " + c).isNotNull();

        // 1) verify with the derived public key (proves derivation is correct)
        VerifyResponse v = verify.verify(new VerifyRequest("detached", MSG, "utf8",
                s.signature(), "base64", s.publicKey(), "auto", c.hash(), c.pss(), null, null));
        assertThat(v.valid()).as("derived-key verify for " + c).isTrue();
        assertThat(v.keyKind()).isEqualTo(c.kind());

        // 2) verify with the ACTUAL public key too
        VerifyResponse v2 = verify.verify(new VerifyRequest("detached", MSG, "utf8",
                s.signature(), "base64", PemUtil.toPem(kp.getPublic()), "auto", c.hash(), c.pss(), null, null));
        assertThat(v2.valid()).isTrue();

        // 3) hex signature encoding verifies as well
        VerifyResponse v3 = verify.verify(new VerifyRequest("detached", MSG, "utf8",
                s.signatureHex(), "hex", s.publicKey(), "auto", c.hash(), c.pss(), null, null));
        assertThat(v3.valid()).isTrue();

        // 4) tampering the message breaks it
        VerifyResponse bad = verify.verify(new VerifyRequest("detached", MSG + "!", "utf8",
                s.signature(), "base64", s.publicKey(), "auto", c.hash(), c.pss(), null, null));
        assertThat(bad.valid()).isFalse();
    }

    @Test
    void signingWithAPublicKeyIsRejected() {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String pubPem = PemUtil.toPem(kp.getPublic());
        assertThatThrownBy(() -> sign.sign(new SignRequest("hi", "utf8", pubPem, "auto", null, null)))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("PRIVATE key");
    }

    @Test
    void signingWithNoKeyIsRejected() {
        assertThatThrownBy(() -> sign.sign(new SignRequest("hi", "utf8", "", "auto", null, null)))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("private key");
    }

    @Test
    void unsupportedHashIsRejected() {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String privPem = PemUtil.toPem(kp.getPrivate());
        assertThatThrownBy(() -> sign.sign(new SignRequest("hi", "utf8", privPem, "auto", "MD5", null)))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("SHA-256");
    }
}
