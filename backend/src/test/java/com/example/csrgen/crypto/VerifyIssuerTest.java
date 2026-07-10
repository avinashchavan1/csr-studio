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
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class VerifyIssuerTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPairService keys = new KeyPairService();
    private final VerifyService verify = new VerifyService();

    /** A self-signed cert (issuer == subject) with a controllable validity window. */
    private X509Certificate selfSigned(KeyPair kp, String cn, Date from, Date to) throws Exception {
        X500Name dn = new X500Name("CN=" + cn);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                dn, BigInteger.valueOf(System.nanoTime()), from, to, dn, spki);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(b.build(signer));
    }

    private VerifyResponse issuer(String leafPem, String issuerPem) {
        return verify.verify(new VerifyRequest("issuer", null, null, null, null,
                null, null, null, null, leafPem, issuerPem));
    }

    private static Date daysFromNow(int d) {
        return new Date(System.currentTimeMillis() + d * 86_400_000L);
    }

    @Test
    void selfSignedVerifiesAgainstItself() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String pem = PemUtil.toPem(selfSigned(kp, "self.example.com", daysFromNow(-1), daysFromNow(30)));
        VerifyResponse r = issuer(pem, pem);
        assertThat(r.valid()).isTrue();
        assertThat(r.nameChainOk()).isTrue();
        assertThat(r.timeValid()).isTrue();
        assertThat(r.notAfter()).isGreaterThan(r.notBefore());
    }

    @Test
    void wrongIssuerFails() throws Exception {
        KeyPair a = keys.generate(KeyAlgorithm.RSA, 2048, null);
        KeyPair b = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String leaf = PemUtil.toPem(selfSigned(a, "a.example.com", daysFromNow(-1), daysFromNow(30)));
        String other = PemUtil.toPem(selfSigned(b, "b.example.com", daysFromNow(-1), daysFromNow(30)));
        VerifyResponse r = issuer(leaf, other);
        assertThat(r.valid()).isFalse();
        assertThat(r.nameChainOk()).isFalse();
        assertThat(r.reason()).isNotBlank();
    }

    @Test
    void expiredCertReportsTimeInvalidButSignatureValid() throws Exception {
        KeyPair kp = keys.generate(KeyAlgorithm.RSA, 2048, null);
        String pem = PemUtil.toPem(selfSigned(kp, "old.example.com", daysFromNow(-30), daysFromNow(-1)));
        VerifyResponse r = issuer(pem, pem);
        assertThat(r.valid()).isTrue();          // signature is fine
        assertThat(r.timeValid()).isFalse();     // but expired
    }
}
