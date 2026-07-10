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

        String kind = SignatureSupport.keyKind(issuer.getPublicKey());
        return new VerifyResponse(
                sigValid, "issuer", leaf.getSigAlgName(), kind, SignatureSupport.isPqc(kind), reason,
                leaf.getSubjectX500Principal().getName(),
                leaf.getIssuerX500Principal().getName(),
                leaf.getNotBefore().getTime(),
                leaf.getNotAfter().getTime(),
                timeValid, nameChainOk);
    }

    /* ---------------- detached signature ---------------- */

    private VerifyResponse verifyDetached(VerifyRequest req) {
        PublicKey key = loadVerifierKey(req);
        String kind = SignatureSupport.keyKind(key);
        boolean pqc = SignatureSupport.isPqc(kind);

        byte[] message = SignatureSupport.decodeMessage(req.message(), req.messageEncoding());
        if (req.signature() == null || req.signature().isBlank()) {
            throw new CryptoException("Provide the signature to verify.");
        }
        byte[] sig = "hex".equalsIgnoreCase(req.signatureEncoding())
                ? SignatureSupport.hexDecode(req.signature(), "signature")
                : SignatureSupport.base64Decode(req.signature(), "signature");

        String algo = req.algorithm() != null && !req.algorithm().isBlank()
                && !req.algorithm().equalsIgnoreCase("auto")
                ? req.algorithm().trim()
                : SignatureSupport.signatureAlgorithm(kind, req.hash(), Boolean.TRUE.equals(req.rsaPss()));

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

}
