package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.CsrResponse;
import com.example.csrgen.api.dto.SanEntryDto;
import com.example.csrgen.api.dto.SubjectDto;
import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds PKCS#10 CSRs using Bouncy Castle.
 */
@Service
public class CsrService {

    private final KeyPairService keyPairService;
    private final ValidationService validationService;

    public CsrService(KeyPairService keyPairService, ValidationService validationService) {
        this.keyPairService = keyPairService;
        this.validationService = validationService;
    }

    /** Internal build product: the signed CSR plus the key pair and chosen sig algorithm. */
    private record Built(PKCS10CertificationRequest csr, KeyPair keyPair, String sigAlgo) {
    }

    private Built build(CsrRequest req) {
        validationService.validate(req);

        KeyPair keyPair = keyPairService.generate(
                req.keyAlgorithm(), req.keySize(), req.ecCurve());

        String sigAlgo = resolveSignatureAlgorithm(req);

        try {
            X500Name subject = buildSubject(req.subject());

            JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            addExtensions(builder, req);

            ContentSigner signer = new JcaContentSignerBuilder(sigAlgo)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            return new Built(builder.build(signer), keyPair, sigAlgo);
        } catch (OperatorCreationException | IOException e) {
            throw new CryptoException("CSR generation failed: " + e.getMessage(), e);
        }
    }

    public CsrResponse generate(CsrRequest req) {
        Built b = build(req);
        return new CsrResponse(
                PemUtil.toPem(b.csr()),
                PemUtil.toPem("PUBLIC KEY", b.keyPair().getPublic().getEncoded()),
                PemUtil.toPem("PRIVATE KEY", b.keyPair().getPrivate().getEncoded()),
                req.keyAlgorithm().name(),
                b.sigAlgo());
    }

    /**
     * Generates a CSR + private key with control over the RSA private key encoding.
     *
     * @param rsaPkcs1 when true and the key is RSA, emit traditional PKCS#1
     *                 ("BEGIN RSA PRIVATE KEY"); otherwise PKCS#8 ("BEGIN PRIVATE KEY").
     */
    public GeneratedCsr generateDetailed(CsrRequest req, boolean rsaPkcs1) {
        Built b = build(req);
        boolean pkcs1 = rsaPkcs1 && req.keyAlgorithm() == KeyAlgorithm.RSA;
        String keyPem = pkcs1
                ? toPkcs1Pem(b.keyPair())
                : PemUtil.toPem("PRIVATE KEY", b.keyPair().getPrivate().getEncoded());
        return new GeneratedCsr(PemUtil.toPem(b.csr()), keyPem, b.sigAlgo());
    }

    /** Re-encodes a PKCS#8 RSA private key as traditional PKCS#1 PEM. */
    private String toPkcs1Pem(KeyPair keyPair) {
        try {
            var pki = org.bouncycastle.asn1.pkcs.PrivateKeyInfo
                    .getInstance(keyPair.getPrivate().getEncoded());
            byte[] pkcs1 = pki.parsePrivateKey().toASN1Primitive().getEncoded();
            return PemUtil.toPem("RSA PRIVATE KEY", pkcs1);
        } catch (IOException e) {
            throw new CryptoException("PKCS#1 encoding failed: " + e.getMessage(), e);
        }
    }

    private X500Name buildSubject(SubjectDto s) {
        X500NameBuilder b = new X500NameBuilder(BCStyle.INSTANCE);
        b.addRDN(BCStyle.CN, s.commonName());
        addIfPresent(b, BCStyle.O, s.organization());
        addIfPresent(b, BCStyle.OU, s.organizationalUnit());
        addIfPresent(b, BCStyle.L, s.locality());
        addIfPresent(b, BCStyle.ST, s.state());
        addIfPresent(b, BCStyle.C, s.country());
        addIfPresent(b, BCStyle.EmailAddress, s.email());
        return b.build();
    }

    private void addIfPresent(X500NameBuilder b,
                              org.bouncycastle.asn1.ASN1ObjectIdentifier oid, String value) {
        if (StringUtils.hasText(value)) {
            b.addRDN(oid, value.trim());
        }
    }

    /** Builds the SAN + optional keyUsage / extendedKeyUsage into one extensionRequest. */
    private void addExtensions(JcaPKCS10CertificationRequestBuilder builder, CsrRequest req)
            throws IOException {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        boolean any = false;

        List<SanEntryDto> sans = req.subjectAltNames();
        if (sans != null && !sans.isEmpty()) {
            List<GeneralName> names = new ArrayList<>();
            for (SanEntryDto san : sans) {
                names.add(new GeneralName(san.type().tag(), san.value().trim()));
            }
            extGen.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(names.toArray(new GeneralName[0])));
            any = true;
        }

        int ku = keyUsageBits(req.keyUsages());
        if (ku != 0) {
            extGen.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
            any = true;
        }

        List<KeyPurposeId> ekus = extendedKeyUsages(req.extendedKeyUsages());
        if (!ekus.isEmpty()) {
            extGen.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(ekus.toArray(new KeyPurposeId[0])));
            any = true;
        }

        if (any) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }
    }

    private int keyUsageBits(List<String> usages) {
        if (usages == null) {
            return 0;
        }
        int bits = 0;
        for (String u : usages) {
            bits |= switch (u.trim()) {
                case "digitalSignature" -> KeyUsage.digitalSignature;
                case "nonRepudiation", "contentCommitment" -> KeyUsage.nonRepudiation;
                case "keyEncipherment" -> KeyUsage.keyEncipherment;
                case "dataEncipherment" -> KeyUsage.dataEncipherment;
                case "keyAgreement" -> KeyUsage.keyAgreement;
                case "keyCertSign" -> KeyUsage.keyCertSign;
                case "cRLSign" -> KeyUsage.cRLSign;
                default -> throw new CryptoException("Unknown key usage: " + u);
            };
        }
        return bits;
    }

    private List<KeyPurposeId> extendedKeyUsages(List<String> ekus) {
        if (ekus == null) {
            return List.of();
        }
        List<KeyPurposeId> out = new ArrayList<>();
        for (String e : ekus) {
            out.add(switch (e.trim()) {
                case "serverAuth" -> KeyPurposeId.id_kp_serverAuth;
                case "clientAuth" -> KeyPurposeId.id_kp_clientAuth;
                case "codeSigning" -> KeyPurposeId.id_kp_codeSigning;
                case "emailProtection" -> KeyPurposeId.id_kp_emailProtection;
                case "timeStamping" -> KeyPurposeId.id_kp_timeStamping;
                case "ocspSigning" -> KeyPurposeId.id_kp_OCSPSigning;
                default -> throw new CryptoException("Unknown extended key usage: " + e);
            });
        }
        return out;
    }

    /**
     * Picks a sane default signature algorithm per key type when none supplied.
     */
    private String resolveSignatureAlgorithm(CsrRequest req) {
        if (StringUtils.hasText(req.signatureAlgorithm())) {
            return req.signatureAlgorithm();
        }
        return switch (req.keyAlgorithm()) {
            case RSA -> "SHA256withRSA";
            case EC -> "SHA256withECDSA";
            case ED25519 -> "Ed25519";
        };
    }
}
