package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.VerifyRequest;
import com.example.csrgen.contract.dto.VerifyResponse;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerifyServiceTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPairService keys = new KeyPairService();
    private final VerifyService verify = new VerifyService();

    private static final String MSG = "the quick brown fox";

    private String pubPem(PublicKey k) {
        return PemUtil.toPem(k);
    }

    private String sign(KeyPair kp, String sigAlgo) throws Exception {
        Signature s = Signature.getInstance(sigAlgo, BouncyCastleProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate());
        s.update(MSG.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    private VerifyRequest detached(String msg, String sigB64, String pubPem) {
        return new VerifyRequest("detached", msg, "utf8", sigB64, "base64",
                pubPem, "auto", null, null, null, null);
    }

    private VerifyResponse run(String msg, String sigB64, String pubPem) {
        return verify.verify(detached(msg, sigB64, pubPem));
    }

    @Test
    void verifiesRsa() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String sig = sign(kp, "SHA256withRSA");
        VerifyResponse r = run(MSG, sig, pubPem(kp.getPublic()));
        assertThat(r.valid()).isTrue();
        assertThat(r.keyKind()).isEqualTo("RSA");
        assertThat(r.pqc()).isFalse();
    }

    @Test
    void verifiesEcdsa() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.EC, null, "secp256r1");
        VerifyResponse r = run(MSG, sign(kp, "SHA256withECDSA"), pubPem(kp.getPublic()));
        assertThat(r.valid()).isTrue();
        assertThat(r.keyKind()).isEqualTo("EC");
    }

    @Test
    void verifiesEd25519() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.ED25519, null, null);
        VerifyResponse r = run(MSG, sign(kp, "Ed25519"), pubPem(kp.getPublic()));
        assertThat(r.valid()).isTrue();
        assertThat(r.keyKind()).isEqualTo("ED25519");
    }

    @Test
    void verifiesMlDsaPqc() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.ML_DSA, null, "ML-DSA-65");
        VerifyResponse r = run(MSG, sign(kp, "ML-DSA"), pubPem(kp.getPublic()));
        assertThat(r.valid()).isTrue();
        assertThat(r.keyKind()).isEqualTo("ML-DSA");
        assertThat(r.pqc()).isTrue();
    }

    @Test
    void tamperedMessageFailsGracefully() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.EC, null, "secp256r1");
        String sig = sign(kp, "SHA256withECDSA");
        VerifyResponse r = run(MSG + " tampered", sig, pubPem(kp.getPublic()));
        assertThat(r.valid()).isFalse();
        assertThat(r.reason()).isNotBlank();
    }

    @Test
    void wrongKeyFails() throws Exception {
        KeyPair signer = keys.generate(KeyAlgorithm.RSA, 2048, null);
        KeyPair other = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String sig = sign(signer, "SHA256withRSA");
        VerifyResponse r = run(MSG, sig, pubPem(other.getPublic()));
        assertThat(r.valid()).isFalse();
    }

    @Test
    void privateKeyPastedGivesFriendlyError() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String sig = sign(kp, "SHA256withRSA");
        String privatePem = PemUtil.toPem(kp.getPrivate());
        assertThatThrownBy(() -> run(MSG, sig, privatePem))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("PUBLIC key");
    }

    @Test
    void badBase64SignatureGivesFriendlyError() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        assertThatThrownBy(() -> run(MSG, "!!!not base64!!!", pubPem(kp.getPublic())))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("base64");
    }

    @Test
    void missingVerifierGivesFriendlyError() {
        VerifyRequest req = new VerifyRequest("detached", MSG, "utf8", "AAAA", "base64",
                null, "auto", null, null, null, null);
        assertThatThrownBy(() -> verify.verify(req))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("public key or a certificate");
    }
}
