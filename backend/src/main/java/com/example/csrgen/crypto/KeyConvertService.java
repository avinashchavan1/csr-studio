package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.KeyConvertRequest;
import com.example.csrgen.contract.dto.KeyConvertResponse;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The "paste anything, get every format" key converter. Accepts a private key
 * (PKCS#8 / traditional PKCS#1 / SEC1), a public key, a certificate or a CSR —
 * PEM or bare base64 DER — and returns all representations we can compute:
 * PKCS#8 / traditional PEM, DER, public key, JWK, OpenSSH line and fingerprints.
 * Private keys are processed transiently and never stored.
 */
@Service
public class KeyConvertService {

    public KeyConvertResponse convert(KeyConvertRequest req) {
        String input = req == null ? null : req.input();
        if (input == null || input.isBlank()) {
            throw new CryptoException("Paste a key, certificate or CSR to convert.");
        }
        Parsed p = parse(input.trim());
        List<String> warnings = new ArrayList<>();

        String kind = SignatureSupport.keyKind(p.publicKey != null ? p.publicKey : p.privateKey);
        boolean pqc = SignatureSupport.isPqc(kind);
        String detail = keyDetail(kind, p.publicKey);

        // ---- private-key representations ----
        String pkcs8Pem = null;
        String traditionalPem = null;
        String pkcs8Der = null;
        if (p.privateKey != null) {
            byte[] der = p.privateKey.getEncoded();
            pkcs8Pem = PemUtil.toPem("PRIVATE KEY", der);
            pkcs8Der = Base64.getEncoder().encodeToString(der);
            traditionalPem = traditionalPem(p.privateKey, kind);
        }

        // ---- public-key representations ----
        String publicPem = null;
        String publicDer = null;
        Map<String, String> jwk = null;
        String ssh = null;
        String spkiSha256 = null;
        String spkiPin = null;
        String sshFp = null;
        if (p.publicKey != null) {
            byte[] spki = p.publicKey.getEncoded();
            publicPem = PemUtil.toPem("PUBLIC KEY", spki);
            publicDer = Base64.getEncoder().encodeToString(spki);
            byte[] h = sha256(spki);
            spkiSha256 = hexColon(h);
            spkiPin = Base64.getEncoder().encodeToString(h);
            jwk = jwk(kind, p.publicKey, warnings);
            byte[] sshBlob = sshBlob(kind, p.publicKey, warnings);
            if (sshBlob != null) {
                ssh = sshAlgoName(kind, p.publicKey) + " "
                        + Base64.getEncoder().encodeToString(sshBlob) + " pqcert";
                sshFp = "SHA256:" + Base64.getEncoder().withoutPadding()
                        .encodeToString(sha256(sshBlob));
            }
        } else {
            warnings.add("Couldn't derive the public key from this private key, "
                    + "so public formats are unavailable.");
        }

        return new KeyConvertResponse(p.inputType, kind, detail, pqc,
                pkcs8Pem, traditionalPem, pkcs8Der, publicPem, publicDer,
                jwk, ssh, spkiSha256, spkiPin, sshFp,
                warnings.isEmpty() ? null : warnings);
    }

    /* ---------------- input parsing ---------------- */

    private record Parsed(String inputType, PrivateKey privateKey, PublicKey publicKey) {
    }

    private Parsed parse(String input) {
        String upper = input.toUpperCase();
        if (upper.contains("ENCRYPTED PRIVATE KEY") || upper.contains("PROC-TYPE: 4,ENCRYPTED")) {
            throw new CryptoException("This private key is encrypted. Decrypt it first — e.g. "
                    + "openssl pkcs8 -in key.pem -out plain.pem — then paste the result.");
        }
        JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (upper.contains("-----BEGIN")) {
            try (PEMParser parser = new PEMParser(new StringReader(input))) {
                Object obj = parser.readObject();
                return fromParsedObject(obj, conv);
            } catch (CryptoException e) {
                throw e;
            } catch (Exception e) {
                throw new CryptoException("Couldn't read that PEM block. Make sure it's a complete, "
                        + "unencrypted key, certificate or CSR (nothing truncated).");
            }
        }
        // Bare base64: try each DER shape in turn.
        byte[] der;
        try {
            der = PemUtil.pemToDer(input);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("That input isn't PEM or valid base64. Paste a PEM block "
                    + "(-----BEGIN ...-----) or its bare base64 body.");
        }
        try {
            PrivateKey priv = conv.getPrivateKey(PrivateKeyInfo.getInstance(der));
            return new Parsed("private-key", priv, SignatureSupport.derivePublicKey(priv));
        } catch (Exception ignored) { /* not a PKCS#8 key */ }
        try {
            return new Parsed("public-key", null, conv.getPublicKey(SubjectPublicKeyInfo.getInstance(der)));
        } catch (Exception ignored) { /* not an SPKI */ }
        try {
            return fromParsedObject(new X509CertificateHolder(der), conv);
        } catch (Exception ignored) { /* not a certificate */ }
        try {
            return fromParsedObject(new PKCS10CertificationRequest(der), conv);
        } catch (Exception ignored) { /* not a CSR */ }
        throw new CryptoException("Decoded the base64, but it isn't a key, certificate or CSR "
                + "this server recognises. Supported: RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA, Falcon.");
    }

    private Parsed fromParsedObject(Object obj, JcaPEMKeyConverter conv) throws Exception {
        if (obj instanceof PEMKeyPair pkp) {                     // traditional PKCS#1 / SEC1
            KeyPair kp = conv.getKeyPair(pkp);
            return new Parsed("private-key", kp.getPrivate(), kp.getPublic());
        }
        if (obj instanceof PrivateKeyInfo pki) {                 // PKCS#8
            PrivateKey priv = conv.getPrivateKey(pki);
            return new Parsed("private-key", priv, SignatureSupport.derivePublicKey(priv));
        }
        if (obj instanceof SubjectPublicKeyInfo spki) {
            return new Parsed("public-key", null, conv.getPublicKey(spki));
        }
        if (obj instanceof X509CertificateHolder cert) {
            return new Parsed("certificate", null, conv.getPublicKey(cert.getSubjectPublicKeyInfo()));
        }
        if (obj instanceof PKCS10CertificationRequest csr) {
            return new Parsed("csr", null, conv.getPublicKey(csr.getSubjectPublicKeyInfo()));
        }
        if (obj == null) {
            throw new CryptoException("Couldn't find a PEM block in that input. "
                    + "Paste the whole thing including the -----BEGIN/END----- lines.");
        }
        throw new CryptoException("That PEM type isn't supported here. Paste a private key, "
                + "public key, certificate or CSR.");
    }

    /* ---------------- format encoders ---------------- */

    /**
     * RSA → PKCS#1 "RSA PRIVATE KEY"; EC → SEC1 "EC PRIVATE KEY"; others → null.
     * JcaPEMWriter (inside PemUtil.toPem) emits the traditional encoding for RSA/EC keys.
     */
    private String traditionalPem(PrivateKey priv, String kind) {
        if (!kind.equals("RSA") && !kind.equals("EC")) {
            return null; // Ed25519 / PQC keys have no "traditional" encoding
        }
        try {
            return PemUtil.toPem(priv);
        } catch (Exception e) {
            return null;
        }
    }

    private String keyDetail(String kind, PublicKey pub) {
        if (pub == null) {
            return kind;
        }
        if (pub instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() + "-bit";
        }
        if (kind.equals("EC")) {
            String c = curveName(pub);
            return c != null ? c : "EC";
        }
        if (kind.equals("ED25519")) {
            return "Ed25519";
        }
        return pub.getAlgorithm(); // PQC keys carry the level in the name (ML-DSA-65 etc.)
    }

    /** P-256 / P-384 / P-521 (or the raw curve name) from the SPKI named-curve OID. */
    private String curveName(PublicKey pub) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(
                    spki.getAlgorithm().getParameters());
            String name = org.bouncycastle.asn1.x9.ECNamedCurveTable.getName(oid);
            if (name == null) {
                name = org.bouncycastle.crypto.ec.CustomNamedCurves.getName(oid);
            }
            return switch (name == null ? "" : name) {
                case "prime256v1", "secp256r1" -> "P-256";
                case "secp384r1" -> "P-384";
                case "secp521r1" -> "P-521";
                default -> name;
            };
        } catch (Exception e) {
            return null;
        }
    }

    /* ---- JWK (public, RFC 7517/7518/8037) ---- */

    private Map<String, String> jwk(String kind, PublicKey pub, List<String> warnings) {
        Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
        Map<String, String> jwk = new LinkedHashMap<>();
        try {
            switch (kind) {
                case "RSA" -> {
                    RSAPublicKey rsa = (RSAPublicKey) pub;
                    jwk.put("kty", "RSA");
                    jwk.put("n", url.encodeToString(unsigned(rsa.getModulus())));
                    jwk.put("e", url.encodeToString(unsigned(rsa.getPublicExponent())));
                }
                case "EC" -> {
                    ECPublicKey ec = (ECPublicKey) pub;
                    String crv = curveName(pub);
                    int flen = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
                    jwk.put("kty", "EC");
                    jwk.put("crv", crv);
                    jwk.put("x", url.encodeToString(fixed(ec.getW().getAffineX(), flen)));
                    jwk.put("y", url.encodeToString(fixed(ec.getW().getAffineY(), flen)));
                }
                case "ED25519" -> {
                    jwk.put("kty", "OKP");
                    jwk.put("crv", "Ed25519");
                    jwk.put("x", url.encodeToString(rawPublicBytes(pub)));
                }
                default -> {
                    warnings.add("JWK output isn't standardised yet for " + kind
                            + " keys — use the PEM / DER forms.");
                    return null;
                }
            }
            return jwk;
        } catch (Exception e) {
            warnings.add("Couldn't build the JWK: " + e.getMessage());
            return null;
        }
    }

    /* ---- OpenSSH public key (RFC 4253 wire format) ---- */

    private String sshAlgoName(String kind, PublicKey pub) {
        return switch (kind) {
            case "RSA" -> "ssh-rsa";
            case "EC" -> "ecdsa-sha2-" + sshCurve(pub);
            case "ED25519" -> "ssh-ed25519";
            default -> null;
        };
    }

    private String sshCurve(PublicKey pub) {
        return switch (String.valueOf(curveName(pub))) {
            case "P-256" -> "nistp256";
            case "P-384" -> "nistp384";
            case "P-521" -> "nistp521";
            default -> "unknown";
        };
    }

    private byte[] sshBlob(String kind, PublicKey pub, List<String> warnings) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            switch (kind) {
                case "RSA" -> {
                    RSAPublicKey rsa = (RSAPublicKey) pub;
                    sshString(out, "ssh-rsa".getBytes());
                    sshString(out, rsa.getPublicExponent().toByteArray()); // mpint
                    sshString(out, rsa.getModulus().toByteArray());        // mpint
                }
                case "EC" -> {
                    String curve = sshCurve(pub);
                    if (curve.equals("unknown")) {
                        return null;
                    }
                    byte[] point = ((org.bouncycastle.jce.interfaces.ECPublicKey)
                            toBcEc(pub)).getQ().getEncoded(false);
                    sshString(out, ("ecdsa-sha2-" + curve).getBytes());
                    sshString(out, curve.getBytes());
                    sshString(out, point);
                }
                case "ED25519" -> {
                    sshString(out, "ssh-ed25519".getBytes());
                    sshString(out, rawPublicBytes(pub));
                }
                default -> {
                    warnings.add("OpenSSH format doesn't exist for " + kind
                            + " keys — use the PEM / DER forms.");
                    return null;
                }
            }
            return out.toByteArray();
        } catch (Exception e) {
            warnings.add("Couldn't build the OpenSSH key: " + e.getMessage());
            return null;
        }
    }

    private java.security.Key toBcEc(PublicKey pub) throws Exception {
        if (pub instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
            return pub;
        }
        return java.security.KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(pub.getEncoded()));
    }

    private static void sshString(ByteArrayOutputStream out, byte[] data) {
        out.write((data.length >>> 24) & 0xFF);
        out.write((data.length >>> 16) & 0xFF);
        out.write((data.length >>> 8) & 0xFF);
        out.write(data.length & 0xFF);
        out.writeBytes(data);
    }

    /* ---- byte helpers ---- */

    /** The raw public bytes from the SPKI bit string (Ed25519 point). */
    private byte[] rawPublicBytes(PublicKey pub) {
        return SubjectPublicKeyInfo.getInstance(pub.getEncoded()).getPublicKeyData().getBytes();
    }

    private static byte[] unsigned(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] out = new byte[b.length - 1];
            System.arraycopy(b, 1, out, 0, out.length);
            return out;
        }
        return b;
    }

    private static byte[] fixed(BigInteger n, int len) {
        byte[] u = unsigned(n);
        if (u.length == len) {
            return u;
        }
        byte[] out = new byte[len];
        System.arraycopy(u, 0, out, len - u.length, u.length);
        return out;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new CryptoException("SHA-256 unavailable", e);
        }
    }

    private static String hexColon(byte[] h) {
        StringBuilder sb = new StringBuilder();
        for (byte b : h) {
            if (sb.length() > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
