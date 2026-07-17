package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.SignRequest;
import com.example.csrgen.contract.dto.SignResponse;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Signs a message with a private key — classical (RSA, ECDSA, Ed25519) and
 * post-quantum (ML-DSA, SLH-DSA, Falcon). The key is used transiently and never
 * stored. The matching public key is derived and returned so the signature can be
 * verified immediately.
 */
@Service
public class SignService {

    public SignResponse sign(SignRequest req) {
        if (req.privateKey() == null || req.privateKey().isBlank()) {
            throw new CryptoException("Provide the private key (PEM) to sign with.");
        }
        KeyPair kp = readKeyPair(req.privateKey());
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        String kind = SignatureSupport.keyKind(priv);
        boolean pqc = SignatureSupport.isPqc(kind);
        byte[] message = SignatureSupport.decodeMessage(req.message(), req.messageEncoding());

        String algo = req.algorithm() != null && !req.algorithm().isBlank()
                && !req.algorithm().equalsIgnoreCase("auto")
                ? req.algorithm().trim()
                : SignatureSupport.signatureAlgorithm(kind, req.hash(), Boolean.TRUE.equals(req.rsaPss()));

        try {
            Signature signer = Signature.getInstance(algo, BouncyCastleProvider.PROVIDER_NAME);
            signer.initSign(priv);
            signer.update(message);
            byte[] sig = signer.sign();
            String pubPem = pub != null ? PemUtil.toPem(pub) : null;
            return new SignResponse(Base64.getEncoder().encodeToString(sig),
                    SignatureSupport.toHex(sig), pubPem, algo, kind, pqc);
        } catch (Exception e) {
            throw new CryptoException("Couldn't sign the message: " + e.getMessage(), e);
        }
    }

    /* ---------------- key loading + public-key derivation ---------------- */

    private KeyPair readKeyPair(String pem) {
        String trimmed = pem.trim();
        String upper = trimmed.toUpperCase();
        if (upper.contains("PUBLIC KEY-----")) {
            throw new CryptoException("That's a public key — signing needs the PRIVATE key "
                    + "(\"-----BEGIN PRIVATE KEY-----\").");
        }
        if (upper.contains("CERTIFICATE-----") && !upper.contains("CERTIFICATE REQUEST")) {
            throw new CryptoException("That's a certificate — signing needs the PRIVATE key.");
        }
        try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (obj instanceof PEMKeyPair pkp) {
                return conv.getKeyPair(pkp);            // traditional PEM carries both halves
            }
            if (obj instanceof PrivateKeyInfo pki) {
                PrivateKey priv = conv.getPrivateKey(pki);
                return new KeyPair(SignatureSupport.derivePublicKey(priv), priv);
            }
            throw new CryptoException("Couldn't read a private key from that PEM. Paste an unencrypted "
                    + "private key (\"-----BEGIN PRIVATE KEY-----\").");
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Couldn't read the private key. Paste an unencrypted PEM private key "
                    + "(PKCS#8 or PKCS#1).");
        }
    }

}
