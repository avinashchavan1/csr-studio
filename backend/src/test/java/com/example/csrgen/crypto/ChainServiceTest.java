package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.ChainRequest;
import com.example.csrgen.contract.dto.ChainResponse;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Chain building + validation across orders, algorithms (classical + PQC) and
 * broken-chain shapes.
 */
class ChainServiceTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPairService keys = new KeyPairService();
    private final ChainService chains = new ChainService();

    /* ---------------- tiny cert lab ---------------- */

    private KeyPair gen(String algo, String param) {
        return switch (algo) {
            case "RSA" -> keys.generate(KeyAlgorithm.RSA, Integer.parseInt(param), null);
            case "EC" -> keys.generate(KeyAlgorithm.EC, null, param);
            case "ED25519" -> keys.generate(KeyAlgorithm.ED25519, null, null);
            default -> keys.generate(KeyAlgorithm.ML_DSA, null, param);
        };
    }

    private String signerAlgo(String algo, String param) {
        return switch (algo) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "ED25519" -> "Ed25519";
            default -> param; // PQC signer name is the parameter set
        };
    }

    private X509Certificate issue(String subjectCn, java.security.PublicKey subjectKey,
                                  String issuerCn, PrivateKey issuerKey, String sigAlgo,
                                  boolean ca, Date from, Date to) throws Exception {
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                new X500Name("CN=" + issuerCn), BigInteger.valueOf(System.nanoTime()),
                from, to, new X500Name("CN=" + subjectCn),
                SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(
                ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                   : KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(b.build(signer));
    }

    private static Date days(int d) {
        return new Date(System.currentTimeMillis() + d * 86_400_000L);
    }

    /** root → intermediate → leaf, all same algo family. Returns [leaf, intermediate, root] PEMs. */
    private String[] threeLevel(String algo, String param) throws Exception {
        KeyPair rootKp = gen(algo, param);
        KeyPair intKp = gen(algo, param);
        KeyPair leafKp = gen(algo, param);
        String sig = signerAlgo(algo, param);
        X509Certificate root = issue("Test Root", rootKp.getPublic(), "Test Root",
                rootKp.getPrivate(), sig, true, days(-10), days(3650));
        X509Certificate inter = issue("Test Intermediate", intKp.getPublic(), "Test Root",
                rootKp.getPrivate(), sig, true, days(-9), days(1825));
        X509Certificate leaf = issue("leaf.example.com", leafKp.getPublic(), "Test Intermediate",
                intKp.getPrivate(), sig, false, days(-1), days(365));
        return new String[]{PemUtil.toPem(leaf), PemUtil.toPem(inter), PemUtil.toPem(root)};
    }

    private ChainResponse analyze(String bundle) {
        return chains.analyze(new ChainRequest(bundle));
    }

    /* ---------------- happy paths ---------------- */

    @ParameterizedTest(name = "[{index}] {0} {1} chain, shuffled input → ordered + valid")
    @CsvSource({"RSA,2048", "EC,P-256", "ED25519,-", "PQC,ML-DSA-65", "PQC,FALCON-512"})
    void shuffledBundleIsOrderedAndValid(String algo, String param) throws Exception {
        String[] pems = threeLevel(algo, param);
        // paste in the worst order: root, leaf, intermediate
        ChainResponse r = analyze(pems[2] + pems[0] + pems[1]);

        assertThat(r.complete()).isTrue();
        assertThat(r.allValid()).isTrue();
        assertThat(r.chain()).hasSize(3);
        assertThat(r.chain().get(0).subject()).contains("leaf.example.com");
        assertThat(r.chain().get(1).subject()).contains("Test Intermediate");
        assertThat(r.chain().get(2).subject()).contains("Test Root");
        assertThat(r.chain().get(2).selfSigned()).isTrue();
        assertThat(r.links()).hasSize(2);
        assertThat(r.links()).allSatisfy(l -> {
            assertThat(l.signatureValid()).isTrue();
            assertThat(l.issuerIsCa()).isTrue();
            assertThat(l.issuerCanSignCerts()).isTrue();
            assertThat(l.nameChainOk()).isTrue();
        });
        // corrected bundle contains all three, leaf first
        assertThat(r.orderedPem().indexOf("CERTIFICATE")).isGreaterThan(-1);
        ChainResponse again = analyze(r.orderedPem());
        assertThat(again.allValid()).isTrue();
        assertThat(again.chain().get(0).subject()).contains("leaf.example.com");
    }

    @Test
    void pqcChainIsFlaggedPqc() throws Exception {
        String[] pems = threeLevel("PQC", "ML-DSA-65");
        ChainResponse r = analyze(pems[0] + pems[1] + pems[2]);
        assertThat(r.allValid()).isTrue();
        assertThat(r.chain()).allSatisfy(c -> {
            assertThat(c.pqc()).isTrue();
            assertThat(c.keyKind()).isEqualTo("ML-DSA");
        });
    }

    @Test
    void singleSelfSignedCertIsACompleteChain() throws Exception {
        KeyPair kp = gen("EC", "P-256");
        X509Certificate cert = issue("solo.example.com", kp.getPublic(), "solo.example.com",
                kp.getPrivate(), "SHA256withECDSA", false, days(-1), days(30));
        ChainResponse r = analyze(PemUtil.toPem(cert));
        assertThat(r.complete()).isTrue();
        assertThat(r.chain()).hasSize(1);
        assertThat(r.links()).isEmpty();
        assertThat(r.chain().get(0).selfSigned()).isTrue();
    }

    @Test
    void bareBase64SingleCertIsAccepted() throws Exception {
        KeyPair kp = gen("RSA", "2048");
        X509Certificate cert = issue("bare.example.com", kp.getPublic(), "bare.example.com",
                kp.getPrivate(), "SHA256withRSA", false, days(-1), days(30));
        String bare = java.util.Base64.getEncoder().encodeToString(cert.getEncoded());
        ChainResponse r = analyze(bare);
        assertThat(r.chain()).hasSize(1);
        assertThat(r.chain().get(0).subject()).contains("bare.example.com");
    }

    @Test
    void junkBetweenPemBlocksIsIgnored() throws Exception {
        String[] pems = threeLevel("EC", "P-256");
        String noisy = "subject=leaf\n" + pems[0] + "\nsome banner text\n" + pems[1]
                + "\n# root below\n" + pems[2];
        ChainResponse r = analyze(noisy);
        assertThat(r.complete()).isTrue();
        assertThat(r.chain()).hasSize(3);
    }

    @Test
    void duplicateCertsAreDeduped() throws Exception {
        String[] pems = threeLevel("EC", "P-256");
        ChainResponse r = analyze(pems[0] + pems[0] + pems[1] + pems[2] + pems[1]);
        assertThat(r.chain()).hasSize(3);
        assertThat(r.extras()).isNull();
    }

    /* ---------------- broken chains ---------------- */

    @Test
    void missingIntermediateIsReported() throws Exception {
        String[] pems = threeLevel("RSA", "2048");
        ChainResponse r = analyze(pems[0] + pems[2]); // leaf + root, no intermediate
        assertThat(r.complete()).isFalse();
        assertThat(r.allValid()).isFalse();
        assertThat(r.missingIssuer()).contains("Test Intermediate");
        assertThat(r.warnings()).anySatisfy(w -> assertThat(w).contains("incomplete"));
        // the root can't chain to the leaf, so it's an extra
        assertThat(r.extras()).hasSize(1);
        assertThat(r.extras().get(0).subject()).contains("Test Root");
    }

    @Test
    void expiredLeafFailsValidityButKeepsChainShape() throws Exception {
        KeyPair rootKp = gen("EC", "P-256");
        KeyPair leafKp = gen("EC", "P-256");
        X509Certificate root = issue("Old Root", rootKp.getPublic(), "Old Root",
                rootKp.getPrivate(), "SHA256withECDSA", true, days(-100), days(3650));
        X509Certificate leaf = issue("expired.example.com", leafKp.getPublic(), "Old Root",
                rootKp.getPrivate(), "SHA256withECDSA", false, days(-90), days(-1));
        ChainResponse r = analyze(PemUtil.toPem(leaf) + PemUtil.toPem(root));
        assertThat(r.complete()).isTrue();
        assertThat(r.allValid()).isFalse();
        assertThat(r.chain().get(0).expired()).isTrue();
        assertThat(r.links().get(0).signatureValid()).isTrue();
        assertThat(r.warnings()).anySatisfy(w -> assertThat(w).contains("validity"));
    }

    @Test
    void nonCaIssuerFailsTheCaCheck() throws Exception {
        KeyPair fakeCaKp = gen("EC", "P-256");
        KeyPair leafKp = gen("EC", "P-256");
        // "issuer" is itself an end-entity cert (CA:FALSE) that still signed a leaf
        X509Certificate fakeCa = issue("Not A CA", fakeCaKp.getPublic(), "Not A CA",
                fakeCaKp.getPrivate(), "SHA256withECDSA", false, days(-10), days(365));
        X509Certificate leaf = issue("victim.example.com", leafKp.getPublic(), "Not A CA",
                fakeCaKp.getPrivate(), "SHA256withECDSA", false, days(-1), days(30));
        ChainResponse r = analyze(PemUtil.toPem(leaf) + PemUtil.toPem(fakeCa));
        assertThat(r.complete()).isTrue();
        assertThat(r.allValid()).isFalse();
        assertThat(r.links().get(0).signatureValid()).isTrue();
        assertThat(r.links().get(0).issuerIsCa()).isFalse();
        assertThat(r.links().get(0).issuerCanSignCerts()).isFalse();
    }

    @Test
    void forgedIssuerNameFailsTheSignatureCheck() throws Exception {
        KeyPair realRootKp = gen("EC", "P-256");
        KeyPair attackerKp = gen("EC", "P-256");
        KeyPair leafKp = gen("EC", "P-256");
        X509Certificate realRoot = issue("Real Root", realRootKp.getPublic(), "Real Root",
                realRootKp.getPrivate(), "SHA256withECDSA", true, days(-10), days(3650));
        // leaf CLAIMS "Real Root" issued it, but it's signed by the attacker's key
        X509Certificate forged = issue("forged.example.com", leafKp.getPublic(), "Real Root",
                attackerKp.getPrivate(), "SHA256withECDSA", false, days(-1), days(30));
        ChainResponse r = analyze(PemUtil.toPem(forged) + PemUtil.toPem(realRoot));
        assertThat(r.complete()).isTrue();          // name chain closes at the self-signed root
        assertThat(r.allValid()).isFalse();          // but the link signature is bogus
        assertThat(r.links().get(0).signatureValid()).isFalse();
        assertThat(r.links().get(0).nameChainOk()).isTrue();
    }

    @Test
    void unrelatedCertLandsInExtras() throws Exception {
        String[] pems = threeLevel("EC", "P-256");
        KeyPair otherKp = gen("EC", "P-256");
        X509Certificate stranger = issue("stranger.example.org", otherKp.getPublic(),
                "stranger.example.org", otherKp.getPrivate(), "SHA256withECDSA",
                false, days(-1), days(30));
        ChainResponse r = analyze(pems[0] + pems[1] + pems[2] + PemUtil.toPem(stranger));
        assertThat(r.chain()).hasSize(3);
        assertThat(r.extras()).isNotNull();
        assertThat(r.extras()).anySatisfy(c -> assertThat(c.subject()).contains("stranger"));
        assertThat(r.warnings()).anySatisfy(w -> assertThat(w).contains("aren't part"));
    }

    /* ---------------- errors ---------------- */

    @Test
    void emptyInputIsRejected() {
        assertThatThrownBy(() -> analyze("   "))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Paste one or more");
    }

    @Test
    void garbageIsRejected() {
        assertThatThrownBy(() -> analyze("this is not a certificate"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("isn't a PEM certificate bundle");
    }

    @Test
    void privateKeyPasteIsRefusedLoudly() throws Exception {
        KeyPair kp = gen("EC", "P-256");
        String keyPem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        assertThatThrownBy(() -> analyze(keyPem))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("never paste private keys");
    }

    @Test
    void csrOnlyInputSaysNoCertificatesFound() {
        var g = CryptoTestSupport.csrService()
                .generateDetailed(CryptoTestSupport.rsaRequest("nocert.example.com"), false);
        assertThatThrownBy(() -> analyze(g.csrPem()))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("No certificates found");
    }
}
