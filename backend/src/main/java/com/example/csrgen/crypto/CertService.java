package com.example.csrgen.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Issues a self-signed X.509 certificate from a generated CSR — handy for local testing
 * before a CA signs the real one. Copies the subject + requested extensions from the CSR.
 */
@Service
public class CertService {

    private static final DefaultAlgorithmNameFinder FINDER = new DefaultAlgorithmNameFinder();
    private static final long DAY_MS = 86_400_000L;

    private final CsrParser csrParser;
    private final ConversionService conversionService;

    public CertService(CsrParser csrParser, ConversionService conversionService) {
        this.csrParser = csrParser;
        this.conversionService = conversionService;
    }

    public String selfSign(String csrPem, String keyPem, int days) {
        int validity = Math.max(1, Math.min(days, 3650));
        try {
            PKCS10CertificationRequest csr = csrParser.decode(csrPem);
            PublicKey pub = csrParser.toPublicKey(csr);
            PrivateKey priv = conversionService.readPrivateKey(keyPem);

            X500Name subject = csr.getSubject();
            BigInteger serial = new BigInteger(64, new SecureRandom()).abs().add(BigInteger.ONE);
            Date from = new Date();
            Date to = new Date(from.getTime() + validity * DAY_MS);

            JcaX509v3CertificateBuilder builder =
                    new JcaX509v3CertificateBuilder(subject, serial, from, to, subject, pub);

            // Carry over the SAN + keyUsage/EKU/basicConstraints requested in the CSR.
            Extensions exts = csrParser.extensionsOf(csr);
            if (exts != null) {
                for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
                    builder.addExtension(exts.getExtension(oid));
                }
            }
            // Subject Key Identifier (best practice for a cert).
            try {
                JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        utils.createSubjectKeyIdentifier(pub));
            } catch (Exception ignored) {
                // SKI is non-essential for a test cert
            }

            String sigAlgo = FINDER.getAlgorithmName(csr.getSignatureAlgorithm());
            ContentSigner signer = new JcaContentSignerBuilder(sigAlgo)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priv);
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
            return PemUtil.toPem(cert);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Self-signed certificate generation failed: " + e.getMessage(), e);
        }
    }
}
