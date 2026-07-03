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
        String input = pem == null ? "" : pem.trim();
        if (input.isEmpty()) {
            throw new CryptoException(
                    "Nothing to decode. Paste a certificate signing request — either the full "
                    + "PEM block (starting with \"-----BEGIN CERTIFICATE REQUEST-----\") or just its base64 body.");
        }

        // Guard against the common mistake of pasting the wrong PEM object, so the
        // user gets a precise \"you pasted an X, not a CSR\" message instead of a
        // generic ASN.1 parse failure.
        String upper = input.toUpperCase();
        if (upper.contains("PRIVATE KEY-----")) {
            throw new CryptoException(
                    "That's a private key, not a CSR — and a private key should never be pasted here. "
                    + "Paste your certificate signing request (\"-----BEGIN CERTIFICATE REQUEST-----\") instead.");
        }
        if (upper.contains("BEGIN") && upper.contains("CERTIFICATE-----")
                && !upper.contains("CERTIFICATE REQUEST")) {
            throw new CryptoException(
                    "That looks like an issued X.509 certificate, not a certificate signing request. "
                    + "Paste a \"-----BEGIN CERTIFICATE REQUEST-----\" block instead.");
        }
        if (upper.contains("PUBLIC KEY-----")) {
            throw new CryptoException(
                    "That's a public key, not a CSR. Paste a \"-----BEGIN CERTIFICATE REQUEST-----\" block instead.");
        }
        if (upper.contains("-----BEGIN") && !upper.contains("CERTIFICATE REQUEST")
                && !upper.contains("NEW CERTIFICATE REQUEST")) {
            throw new CryptoException(
                    "This PEM block isn't a certificate signing request. A CSR is labelled "
                    + "\"-----BEGIN CERTIFICATE REQUEST-----\".");
        }

        byte[] der;
        try {
            der = PemUtil.pemToDer(input);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(base64Hint(input), e);
        }
        if (der == null || der.length == 0) {
            throw new CryptoException(
                    "The request decoded to no data — the text is probably truncated. "
                    + "Copy the entire CSR (including the last line) and try again.");
        }

        try {
            return new PKCS10CertificationRequest(der);
        } catch (IOException | RuntimeException e) {
            throw new CryptoException(
                    "The text decoded, but it isn't a valid PKCS#10 certificate signing request. "
                    + "It may be truncated, corrupted, or a different kind of file (a certificate or key). "
                    + "Re-copy the complete request and try again.", e);
        }
    }

    /**
     * Explains why a bare (un-armored) input couldn't be base64-decoded, in plain
     * language: stray non-base64 characters vs. a length/padding problem.
     */
    private String base64Hint(String input) {
        String cleaned = input.replaceAll("\\s+", "");
        String offenders = cleaned.replaceAll("[A-Za-z0-9+/=]", "");
        if (!offenders.isEmpty()) {
            String sample = offenders.chars().distinct().limit(6)
                    .collect(StringBuilder::new, (sb, c) -> sb.append((char) c), StringBuilder::append)
                    .toString();
            return "This doesn't look like a CSR. It contains characters that aren't valid base64 (for example: "
                    + sample + "). Paste only the certificate request — a PEM block, or its base64 body with no extra text.";
        }
        return "The base64 body looks incomplete or corrupted (its length isn't a valid multiple of 4). "
                + "Copy the entire request and make sure nothing was cut off.";
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

        org.bouncycastle.asn1.x509.Extensions exts = extensionsOf(csr);
        List<String> keyUsages = extractKeyUsages(exts);
        List<String> ekus = extractEkus(exts);
        String basicConstraints = extractBasicConstraints(exts);

        return new CsrParseResponse(
                subject.toString(), fields, sans, keyAlgo, keySize, sigAlgo, sigValid,
                keyUsages, ekus, basicConstraints);
    }

    public org.bouncycastle.asn1.x509.Extensions extensionsOf(PKCS10CertificationRequest csr) {
        var attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs == null || attrs.length == 0) {
            return null;
        }
        var values = attrs[0].getAttributeValues();
        return values.length == 0 ? null : org.bouncycastle.asn1.x509.Extensions.getInstance(values[0]);
    }

    private List<String> extractKeyUsages(org.bouncycastle.asn1.x509.Extensions exts) {
        if (exts == null) {
            return null;
        }
        org.bouncycastle.asn1.x509.KeyUsage ku =
                org.bouncycastle.asn1.x509.KeyUsage.fromExtensions(exts);
        if (ku == null) {
            return null;
        }
        record U(int bit, String name) {
        }
        List<U> all = List.of(
                new U(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature, "digitalSignature"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation, "nonRepudiation"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment, "keyEncipherment"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment, "dataEncipherment"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement, "keyAgreement"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign, "keyCertSign"),
                new U(org.bouncycastle.asn1.x509.KeyUsage.cRLSign, "cRLSign"));
        List<String> out = new ArrayList<>();
        for (U u : all) {
            if (ku.hasUsages(u.bit())) {
                out.add(u.name());
            }
        }
        return out.isEmpty() ? null : out;
    }

    private List<String> extractEkus(org.bouncycastle.asn1.x509.Extensions exts) {
        if (exts == null) {
            return null;
        }
        org.bouncycastle.asn1.x509.ExtendedKeyUsage eku =
                org.bouncycastle.asn1.x509.ExtendedKeyUsage.fromExtensions(exts);
        if (eku == null) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (org.bouncycastle.asn1.x509.KeyPurposeId id : eku.getUsages()) {
            out.add(ekuName(id));
        }
        return out.isEmpty() ? null : out;
    }

    private String ekuName(org.bouncycastle.asn1.x509.KeyPurposeId id) {
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth)) return "serverAuth";
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth)) return "clientAuth";
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning)) return "codeSigning";
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_emailProtection)) return "emailProtection";
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping)) return "timeStamping";
        if (id.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)) return "ocspSigning";
        return id.getId();
    }

    private String extractBasicConstraints(org.bouncycastle.asn1.x509.Extensions exts) {
        if (exts == null) {
            return null;
        }
        org.bouncycastle.asn1.x509.BasicConstraints bc =
                org.bouncycastle.asn1.x509.BasicConstraints.fromExtensions(exts);
        if (bc == null) {
            return null;
        }
        if (!bc.isCA()) {
            return "CA:FALSE";
        }
        return bc.getPathLenConstraint() != null
                ? "CA:TRUE, pathlen:" + bc.getPathLenConstraint()
                : "CA:TRUE";
    }

    /** SHA-256 fingerprint of the SubjectPublicKeyInfo (DER) — hex + base64 SPKI pin. */
    public record Fingerprint(String sha256, String pin) {
    }

    public Fingerprint publicKeyFingerprint(PKCS10CertificationRequest csr) {
        try {
            byte[] spki = csr.getSubjectPublicKeyInfo().getEncoded();
            byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(spki);
            StringBuilder hex = new StringBuilder();
            for (byte b : h) {
                if (hex.length() > 0) {
                    hex.append(':');
                }
                hex.append(String.format("%02X", b));
            }
            return new Fingerprint(hex.toString(), java.util.Base64.getEncoder().encodeToString(h));
        } catch (Exception e) {
            return new Fingerprint(null, null);
        }
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
            throw new CryptoException(
                    "The CSR was read, but its public key uses an algorithm this server can't decode. "
                    + "Supported: RSA, ECDSA, Ed25519, and post-quantum ML-DSA / SLH-DSA / Falcon.", e);
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
                result.add(new SanEntryDto(type, sanValue(type, gn)));
            }
        }
        return result;
    }

    /**
     * Renders a SAN value. IP addresses come as raw ASN.1 octets — decode them to a
     * dotted-quad (4 bytes) or IPv6 literal (16 bytes) instead of a hex dump.
     */
    private String sanValue(SanType type, GeneralName gn) {
        if (type == SanType.IP) {
            try {
                byte[] octets = org.bouncycastle.asn1.ASN1OctetString
                        .getInstance(gn.getName()).getOctets();
                return java.net.InetAddress.getByAddress(octets).getHostAddress();
            } catch (Exception e) {
                // fall through to default rendering
            }
        }
        return gn.getName().toString();
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
