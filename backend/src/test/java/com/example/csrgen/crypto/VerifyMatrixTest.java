package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.VerifyRequest;
import com.example.csrgen.contract.dto.VerifyResponse;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Combinatorial signature-verification matrix: every algorithm (classical + PQC) is
 * signed and then verified across message encodings (utf8/base64/hex), signature
 * encodings (base64/hex), hash variants, cert-as-verifier, and the negative paths
 * (tampered message, wrong key). Verification correctness is business-critical.
 */
class VerifyMatrixTest {

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final VerifyService verify = new VerifyService();
    private static final KeyPairService KEYS = new KeyPairService();
    private static final byte[] MSG = "verify-matrix ✓ 12345 — αβγ".getBytes(StandardCharsets.UTF_8);

    /* ---------- precomputed signed artifacts (one keygen per algo/hash) ---------- */

    record Artifact(String name, String sigAlgo, String hash, boolean pss, boolean pqc,
                    String pubPem, String otherPubPem, String certPem, byte[] sig) {
    }

    record Case(Artifact a, String msgEnc, String sigEnc, String mutation, boolean expectValid) {
        @Override public String toString() {
            return a.name() + " msg=" + msgEnc + " sig=" + sigEnc + " " + mutation;
        }
    }

    private static String hexNoDash(String h) { return h.replace("-", ""); }

    private static byte[] signWith(KeyPair kp, String sigAlgo) throws Exception {
        Signature s = Signature.getInstance(sigAlgo, BouncyCastleProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate());
        s.update(MSG);
        return s.sign();
    }

    private static String pem(PublicKey k) { return PemUtil.toPem(k); }

    private static X509Certificate selfSigned(KeyPair kp, String sigAlgo) throws Exception {
        X500Name dn = new X500Name("CN=verify.example.com");
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(dn, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L), dn, spki);
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(b.build(signer));
    }

    private static Artifact make(String name, KeyAlgorithm alg, Integer rsa, String curveOrParam,
                                 String hash, boolean pss, boolean pqc, boolean withCert) {
        try {
            KeyPair kp = KEYS.generate(alg, rsa, curveOrParam);
            KeyPair other = KEYS.generate(alg, rsa, curveOrParam);
            String sigAlgo;
            String kind = name.split(" ")[0];
            if (kind.equals("RSA")) sigAlgo = pss ? hexNoDash(hash) + "withRSAandMGF1" : hexNoDash(hash) + "withRSA";
            else if (kind.equals("EC")) sigAlgo = hexNoDash(hash) + "withECDSA";
            else if (kind.equals("Ed25519")) sigAlgo = "Ed25519";
            else if (kind.startsWith("ML-DSA")) sigAlgo = "ML-DSA";
            else if (kind.startsWith("SLH-DSA")) sigAlgo = "SLH-DSA";
            else sigAlgo = "Falcon";
            byte[] sig = signWith(kp, sigAlgo);
            String cert = withCert ? PemUtil.toPem(selfSigned(kp, sigAlgo)) : null;
            return new Artifact(name, sigAlgo, hash, pss, pqc, pem(kp.getPublic()), pem(other.getPublic()), cert, sig);
        } catch (Exception e) {
            throw new RuntimeException("setup failed for " + name, e);
        }
    }

    static Stream<Arguments> cases() {
        List<Artifact> arts = new ArrayList<>();
        // rich (with cert + hash variants added below)
        arts.add(make("RSA pkcs1", KeyAlgorithm.RSA, 2048, null, "SHA-256", false, false, true));
        arts.add(make("RSA pss", KeyAlgorithm.RSA, 2048, null, "SHA-256", true, false, false));
        arts.add(make("EC P-256", KeyAlgorithm.EC, null, "P-256", "SHA-256", false, false, true));
        arts.add(make("EC P-384", KeyAlgorithm.EC, null, "P-384", "SHA-256", false, false, false));
        arts.add(make("EC P-521", KeyAlgorithm.EC, null, "P-521", "SHA-256", false, false, false));
        arts.add(make("Ed25519", KeyAlgorithm.ED25519, null, null, "SHA-256", false, false, true));
        arts.add(make("ML-DSA-44", KeyAlgorithm.ML_DSA, null, "ML-DSA-44", "SHA-256", false, true, false));
        arts.add(make("ML-DSA-65", KeyAlgorithm.ML_DSA, null, "ML-DSA-65", "SHA-256", false, true, true));
        arts.add(make("ML-DSA-87", KeyAlgorithm.ML_DSA, null, "ML-DSA-87", "SHA-256", false, true, false));
        arts.add(make("SLH-DSA", KeyAlgorithm.SLH_DSA, null, "SLH-DSA-SHA2-128S", "SHA-256", false, true, false));
        arts.add(make("Falcon-512", KeyAlgorithm.FALCON, null, "Falcon-512", "SHA-256", false, true, false));
        arts.add(make("Falcon-1024", KeyAlgorithm.FALCON, null, "Falcon-1024", "SHA-256", false, true, false));
        // extra hash variants for RSA/EC
        arts.add(make("RSA pkcs1", KeyAlgorithm.RSA, 2048, null, "SHA-384", false, false, false));
        arts.add(make("RSA pkcs1", KeyAlgorithm.RSA, 2048, null, "SHA-512", false, false, false));
        arts.add(make("EC P-256", KeyAlgorithm.EC, null, "P-256", "SHA-512", false, false, false));

        String[] msgEncs = {"utf8", "base64", "hex"};
        String[] sigEncs = {"base64", "hex"};
        List<Arguments> out = new ArrayList<>();
        for (Artifact a : arts) {
            for (String me : msgEncs) {
                for (String se : sigEncs) {
                    out.add(Arguments.of(new Case(a, me, se, "none", true)));
                }
            }
            out.add(Arguments.of(new Case(a, "utf8", "base64", "tamper", false)));
            out.add(Arguments.of(new Case(a, "utf8", "base64", "wrongkey", false)));
            if (a.certPem() != null) {
                out.add(Arguments.of(new Case(a, "utf8", "base64", "cert", true)));
            }
        }
        return out.stream();
    }

    private String encodeMsg(String enc, boolean tamper) {
        byte[] m = tamper ? "totally different message".getBytes(StandardCharsets.UTF_8) : MSG;
        return switch (enc) {
            case "base64" -> Base64.getEncoder().encodeToString(m);
            case "hex" -> toHex(m);
            default -> new String(m, StandardCharsets.UTF_8);
        };
    }

    private String encodeSig(byte[] sig, String enc) {
        return enc.equals("hex") ? toHex(sig) : Base64.getEncoder().encodeToString(sig);
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void verifyMatrix(Case c) {
        boolean tamper = c.mutation().equals("tamper");
        boolean wrongKey = c.mutation().equals("wrongkey");
        boolean cert = c.mutation().equals("cert");

        String msg = encodeMsg(c.msgEnc(), tamper);
        String sig = encodeSig(c.a().sig(), c.sigEnc());
        String pub = wrongKey ? c.a().otherPubPem() : (cert ? null : c.a().pubPem());
        String certPem = cert ? c.a().certPem() : null;

        VerifyRequest req = new VerifyRequest("detached", msg, c.msgEnc(), sig, c.sigEnc(),
                pub, "auto", c.a().hash(), c.a().pss(), certPem, null);

        VerifyResponse r = verify.verify(req);
        assertThat(r.valid())
                .as("expected valid=%s for %s", c.expectValid(), c)
                .isEqualTo(c.expectValid());
        assertThat(r.pqc()).isEqualTo(c.a().pqc());
        if (!c.expectValid()) {
            assertThat(r.reason()).isNotBlank();
        }
    }
}
