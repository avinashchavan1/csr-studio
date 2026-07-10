package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.VerifyRequest;
import com.example.csrgen.contract.dto.VerifyResponse;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Verifies digital signatures — classical (RSA, ECDSA, Ed25519) and post-quantum
 * (ML-DSA, SLH-DSA, Falcon). Public-key only; no secrets, no storage.
 */
@Service
public class VerifyService {

    public VerifyResponse verify(VerifyRequest req) {
        String mode = req.mode() == null || req.mode().isBlank() ? "detached" : req.mode().trim().toLowerCase();
        if (mode.equals("detached")) {
            return verifyDetached(req);
        }
        if (mode.equals("issuer")) {
            return verifyIssuer(req);
        }
        throw new CryptoException("Unknown verification mode: '" + req.mode()
                + "'. Use 'detached' or 'issuer'.");
    }

    /* ---------------- certificate signed by issuer ---------------- */

    private VerifyResponse verifyIssuer(VerifyRequest req) {
        if (req.certificate() == null || req.certificate().isBlank()) {
            throw new CryptoException("Provide the certificate to check (the leaf/end-entity certificate).");
        }
        if (req.issuerCertificate() == null || req.issuerCertificate().isBlank()) {
            throw new CryptoException("Provide the issuer (CA) certificate that supposedly signed it.");
        }
        X509Certificate leaf = readCertificate(req.certificate());
        X509Certificate issuer = readCertificate(req.issuerCertificate());

        boolean nameChainOk = leaf.getIssuerX500Principal().equals(issuer.getSubjectX500Principal());

        boolean sigValid;
        String reason = null;
        try {
            leaf.verify(issuer.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
            sigValid = true;
        } catch (java.security.SignatureException | java.security.InvalidKeyException e) {
            sigValid = false;
            reason = "The issuer's key did not sign this certificate. "
                    + (nameChainOk ? "" : "The issuer name also doesn't match — this is likely the wrong CA certificate.");
        } catch (Exception e) {
            throw new CryptoException("Couldn't verify the certificate against the issuer: " + e.getMessage(), e);
        }

        boolean timeValid;
        try {
            leaf.checkValidity();
            timeValid = true;
        } catch (Exception e) {
            timeValid = false;
            if (reason == null) {
                reason = "The signature checks out, but the certificate is outside its validity window "
                        + "(expired or not yet valid).";
            }
        }
        if (sigValid && !nameChainOk && reason == null) {
            reason = "The signature verified, but the leaf's issuer name doesn't match the CA's subject name.";
        }

        String kind = keyKind(issuer.getPublicKey());
        return new VerifyResponse(
                sigValid, "issuer", leaf.getSigAlgName(), kind, isPqc(kind), reason,
                leaf.getSubjectX500Principal().getName(),
                leaf.getIssuerX500Principal().getName(),
                leaf.getNotBefore().getTime(),
                leaf.getNotAfter().getTime(),
                timeValid, nameChainOk);
    }

    /* ---------------- detached signature ---------------- */

    private VerifyResponse verifyDetached(VerifyRequest req) {
        PublicKey key = loadVerifierKey(req);
        String kind = keyKind(key);
        boolean pqc = isPqc(kind);

        byte[] message = decodeMessage(req.message(), req.messageEncoding());
        byte[] sig = decodeSignature(req.signature(), req.signatureEncoding());

        String algo = resolveAlgorithm(req.algorithm(), key, kind, req.hash(),
                Boolean.TRUE.equals(req.rsaPss()));

        try {
            Signature verifier = Signature.getInstance(algo, BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(key);
            verifier.update(message);
            boolean ok = verifier.verify(sig);
            return VerifyResponse.detached(ok, algo, kind, pqc,
                    ok ? null : "The signature does not match this message and public key. "
                            + "Check you selected the right key, algorithm/hash, and signature encoding.");
        } catch (java.security.SignatureException e) {
            // Malformed signature bytes (e.g. wrong encoding) — a verification failure, not a crash.
            return VerifyResponse.detached(false, algo, kind, pqc,
                    "The signature couldn't be read for this algorithm — it may be the wrong "
                    + "encoding (base64 vs hex) or not a " + algo + " signature.");
        } catch (Exception e) {
            throw new CryptoException("Couldn't verify the signature: " + e.getMessage(), e);
        }
    }

    /* ---------------- key loading ---------------- */

    private PublicKey loadVerifierKey(VerifyRequest req) {
        boolean hasKey = req.publicKey() != null && !req.publicKey().isBlank();
        boolean hasCert = req.certificate() != null && !req.certificate().isBlank();
        if (!hasKey && !hasCert) {
            throw new CryptoException("Provide a public key or a certificate (PEM) to verify against.");
        }
        if (hasCert) {
            return readCertificate(req.certificate()).getPublicKey();
        }
        return readPublicKey(req.publicKey());
    }

    private PublicKey readPublicKey(String pem) {
        String trimmed = pem.trim();
        String upper = trimmed.toUpperCase();
        if (upper.contains("PRIVATE KEY-----")) {
            throw new CryptoException("That's a private key — verification needs the PUBLIC key "
                    + "(\"-----BEGIN PUBLIC KEY-----\") or a certificate. Never paste a private key here.");
        }
        if (upper.contains("CERTIFICATE-----") && !upper.contains("CERTIFICATE REQUEST")) {
            // A certificate pasted into the key box — accept it.
            return readCertificate(trimmed).getPublicKey();
        }
        try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (obj instanceof SubjectPublicKeyInfo spki) {
                return conv.getPublicKey(spki);
            }
            if (obj instanceof org.bouncycastle.cert.X509CertificateHolder holder) {
                return conv.getPublicKey(holder.getSubjectPublicKeyInfo());
            }
            if (obj instanceof PrivateKeyInfo) {
                throw new CryptoException("That's a private key — paste the PUBLIC key instead.");
            }
            // Fall back: maybe a bare base64 SubjectPublicKeyInfo (no armor).
            byte[] der = PemUtil.pemToDer(trimmed);
            return conv.getPublicKey(SubjectPublicKeyInfo.getInstance(der));
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Couldn't read the public key. Paste a PEM public key "
                    + "(\"-----BEGIN PUBLIC KEY-----\") or a certificate.");
        }
    }

    private X509Certificate readCertificate(String pem) {
        try {
            byte[] der = PemUtil.pemToDer(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CryptoException("Couldn't read the certificate. Paste a valid X.509 certificate PEM "
                    + "(\"-----BEGIN CERTIFICATE-----\").");
        }
    }

    /* ---------------- algorithm resolution ---------------- */

    static String keyKind(PublicKey key) {
        String a = key.getAlgorithm() == null ? "" : key.getAlgorithm().toUpperCase();
        if (a.contains("RSA")) return "RSA";
        if (a.equals("EC") || a.contains("ECDSA")) return "EC";
        if (a.contains("ED25519") || a.contains("EDDSA")) return "ED25519";
        if (a.contains("ML-DSA") || a.contains("DILITHIUM")) return "ML-DSA";
        if (a.contains("SLH-DSA") || a.contains("SPHINCS")) return "SLH-DSA";
        if (a.contains("FALCON")) return "Falcon";
        return key.getAlgorithm();
    }

    private static boolean isPqc(String kind) {
        return kind.equals("ML-DSA") || kind.equals("SLH-DSA") || kind.equals("Falcon");
    }

    private String resolveAlgorithm(String requested, PublicKey key, String kind, String hash, boolean pss) {
        if (requested != null && !requested.isBlank() && !requested.equalsIgnoreCase("auto")) {
            return requested.trim();
        }
        String h = normalizeHash(hash);
        switch (kind) {
            case "RSA":
                return pss ? h + "withRSAandMGF1" : h + "withRSA";
            case "EC":
                return h + "withECDSA";
            case "ED25519":
                return "Ed25519";
            case "ML-DSA":
                return "ML-DSA";
            case "SLH-DSA":
                return "SLH-DSA";
            case "Falcon":
                return "Falcon";
            default:
                throw new CryptoException("Can't determine a signature algorithm for a "
                        + key.getAlgorithm() + " key. Supported: RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA, Falcon.");
        }
    }

    /** "SHA-256" / "sha256" → "SHA256"; default SHA256. */
    private String normalizeHash(String hash) {
        if (hash == null || hash.isBlank()) return "SHA256";
        String h = hash.trim().toUpperCase().replace("-", "");
        if (h.equals("SHA256") || h.equals("SHA384") || h.equals("SHA512")) return h;
        throw new CryptoException("Unsupported hash '" + hash + "'. Use SHA-256, SHA-384 or SHA-512.");
    }

    /* ---------------- byte decoding ---------------- */

    private byte[] decodeMessage(String message, String encoding) {
        String m = message == null ? "" : message;
        String enc = encoding == null || encoding.isBlank() ? "utf8" : encoding.trim().toLowerCase();
        switch (enc) {
            case "utf8":
            case "text":
                return m.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            case "base64":
                return decodeBase64(m, "message");
            case "hex":
                return decodeHex(m, "message");
            default:
                throw new CryptoException("Unknown message encoding '" + encoding + "'. Use utf8, base64 or hex.");
        }
    }

    private byte[] decodeSignature(String signature, String encoding) {
        if (signature == null || signature.isBlank()) {
            throw new CryptoException("Provide the signature to verify.");
        }
        String enc = encoding == null || encoding.isBlank() ? "base64" : encoding.trim().toLowerCase();
        return enc.equals("hex") ? decodeHex(signature, "signature") : decodeBase64(signature, "signature");
    }

    private byte[] decodeBase64(String s, String what) {
        try {
            return Base64.getDecoder().decode(s.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw new CryptoException("The " + what + " isn't valid base64. Check the encoding "
                    + "(is it hex instead?) and that nothing was truncated.");
        }
    }

    private byte[] decodeHex(String s, String what) {
        String h = s.replaceAll("\\s+", "").replaceFirst("^0[xX]", "");
        if (h.length() % 2 != 0 || !h.matches("[0-9a-fA-F]*")) {
            throw new CryptoException("The " + what + " isn't valid hex. Use pairs of 0-9/a-f "
                    + "(or switch the encoding to base64).");
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
