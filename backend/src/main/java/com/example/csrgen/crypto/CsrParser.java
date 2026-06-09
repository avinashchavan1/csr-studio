package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrParseResponse;
import com.example.csrgen.api.dto.SanEntryDto;
import com.example.csrgen.domain.SanType;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decodes and inspects PKCS#10 CSRs.
 */
@Service
public class CsrParser {

    private static final DefaultAlgorithmNameFinder ALGO_FINDER = new DefaultAlgorithmNameFinder();

    public PKCS10CertificationRequest decode(String pem) {
        try {
            return new PKCS10CertificationRequest(PemUtil.pemToDer(pem));
        } catch (IOException | IllegalArgumentException e) {
            throw new CryptoException("Could not parse CSR: " + e.getMessage(), e);
        }
    }

    public CsrParseResponse parse(String pem) {
        PKCS10CertificationRequest csr = decode(pem);

        X500Name subject = csr.getSubject();
        Map<String, String> fields = extractSubjectFields(subject);
        List<SanEntryDto> sans = extractSans(csr);

        SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
        PublicKey publicKey = toPublicKey(csr);
        String keyAlgo = normalizeKeyAlgo(publicKey.getAlgorithm());
        Integer keySize = keySize(publicKey);
        String sigAlgo = ALGO_FINDER.getAlgorithmName(csr.getSignatureAlgorithm());
        boolean sigValid = verifySignature(csr, spki);

        return new CsrParseResponse(
                subject.toString(), fields, sans, keyAlgo, keySize, sigAlgo, sigValid);
    }

    public boolean verifySignature(PKCS10CertificationRequest csr, SubjectPublicKeyInfo spki) {
        try {
            return csr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(spki));
        } catch (Exception e) {
            return false;
        }
    }

    public PublicKey toPublicKey(PKCS10CertificationRequest csr) {
        try {
            return new JcaPKCS10CertificationRequest(csr)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey();
        } catch (Exception e) {
            throw new CryptoException("Could not read CSR public key: " + e.getMessage(), e);
        }
    }

    private Map<String, String> extractSubjectFields(X500Name subject) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (RDN rdn : subject.getRDNs()) {
            ASN1ObjectIdentifier oid = rdn.getFirst().getType();
            String value = IETFUtils.valueToString(rdn.getFirst().getValue());
            fields.put(label(oid), value);
        }
        return fields;
    }

    private String label(ASN1ObjectIdentifier oid) {
        if (BCStyle.CN.equals(oid)) return "commonName";
        if (BCStyle.O.equals(oid)) return "organization";
        if (BCStyle.OU.equals(oid)) return "organizationalUnit";
        if (BCStyle.L.equals(oid)) return "locality";
        if (BCStyle.ST.equals(oid)) return "state";
        if (BCStyle.C.equals(oid)) return "country";
        if (BCStyle.EmailAddress.equals(oid)) return "email";
        return oid.getId();
    }

    private List<SanEntryDto> extractSans(PKCS10CertificationRequest csr) {
        List<SanEntryDto> result = new ArrayList<>();
        var attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs == null || attrs.length == 0) {
            return result;
        }
        ASN1Encodable[] values = attrs[0].getAttributeValues();
        if (values.length == 0) {
            return result;
        }
        Extensions extensions = Extensions.getInstance(values[0]);
        GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (gns == null) {
            return result;
        }
        for (GeneralName gn : gns.getNames()) {
            SanType type = sanType(gn.getTagNo());
            if (type != null) {
                result.add(new SanEntryDto(type, gn.getName().toString()));
            }
        }
        return result;
    }

    private SanType sanType(int tag) {
        for (SanType t : SanType.values()) {
            if (t.tag() == tag) {
                return t;
            }
        }
        return null;
    }

    private String normalizeKeyAlgo(String jcaName) {
        String n = jcaName.toUpperCase();
        if (n.startsWith("RSA")) return "RSA";
        if (n.startsWith("EC") || n.contains("ECDSA")) return "EC";
        if (n.contains("ED25519")) return "ED25519";
        return jcaName;
    }

    private Integer keySize(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (key instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        if ("Ed25519".equalsIgnoreCase(key.getAlgorithm())) {
            return 256;
        }
        return null;
    }
}
