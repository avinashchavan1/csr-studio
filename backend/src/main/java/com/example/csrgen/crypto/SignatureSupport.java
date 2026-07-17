package com.example.csrgen.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Shared helpers for signing and verifying — key classification, JCA signature
 * algorithm resolution, and message/signature byte decoding. Kept in one place so
 * {@link SignService} and {@link VerifyService} agree exactly.
 */
final class SignatureSupport {

    private SignatureSupport() {
    }

    /** RSA | EC | ED25519 | ML-DSA | SLH-DSA | Falcon (or the raw JCA name). */
    static String keyKind(Key key) {
        String a = key.getAlgorithm() == null ? "" : key.getAlgorithm().toUpperCase();
        if (a.contains("RSA")) return "RSA";
        if (a.equals("EC") || a.contains("ECDSA")) return "EC";
        if (a.contains("ED25519") || a.contains("EDDSA")) return "ED25519";
        if (a.contains("ML-DSA") || a.contains("DILITHIUM")) return "ML-DSA";
        if (a.contains("SLH-DSA") || a.contains("SPHINCS")) return "SLH-DSA";
        if (a.contains("FALCON")) return "Falcon";
        return key.getAlgorithm();
    }

    static boolean isPqc(String kind) {
        return kind.equals("ML-DSA") || kind.equals("SLH-DSA") || kind.equals("Falcon");
    }

    /** The JCA signature algorithm name for a key kind + hash + RSA padding. */
    static String signatureAlgorithm(String kind, String hash, boolean pss) {
        String h = normalizeHash(hash);
        return switch (kind) {
            case "RSA" -> pss ? h + "withRSAandMGF1" : h + "withRSA";
            case "EC" -> h + "withECDSA";
            case "ED25519" -> "Ed25519";
            case "ML-DSA" -> "ML-DSA";
            case "SLH-DSA" -> "SLH-DSA";
            case "Falcon" -> "Falcon";
            default -> throw new CryptoException("Unsupported key type '" + kind
                    + "'. Supported: RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA, Falcon.");
        };
    }

    /** "SHA-256"/"sha256" → "SHA256"; default SHA256. */
    static String normalizeHash(String hash) {
        if (hash == null || hash.isBlank()) return "SHA256";
        String h = hash.trim().toUpperCase().replace("-", "");
        if (h.equals("SHA256") || h.equals("SHA384") || h.equals("SHA512")) return h;
        throw new CryptoException("Unsupported hash '" + hash + "'. Use SHA-256, SHA-384 or SHA-512.");
    }

    static byte[] decodeMessage(String message, String encoding) {
        String m = message == null ? "" : message;
        String enc = encoding == null || encoding.isBlank() ? "utf8" : encoding.trim().toLowerCase();
        return switch (enc) {
            case "utf8", "text" -> m.getBytes(StandardCharsets.UTF_8);
            case "base64" -> base64Decode(m, "message");
            case "hex" -> hexDecode(m, "message");
            default -> throw new CryptoException("Unknown message encoding '" + encoding + "'. Use utf8, base64 or hex.");
        };
    }

    static byte[] base64Decode(String s, String what) {
        try {
            return Base64.getDecoder().decode(s.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw new CryptoException("The " + what + " isn't valid base64. Check the encoding "
                    + "(is it hex instead?) and that nothing was truncated.");
        }
    }

    static byte[] hexDecode(String s, String what) {
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

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * Derives the public key from a private key. Modern BC keys (Ed25519, ML-DSA,
     * SLH-DSA, Falcon) expose getPublicKey(); RSA is rebuilt from CRT params; EC is
     * derived by scalar-multiplying the base point. Returns null if none applies.
     */
    static PublicKey derivePublicKey(PrivateKey priv) {
        // BC key types (Ed25519 + PQC) expose getPublicKey() directly.
        try {
            Method m = priv.getClass().getMethod("getPublicKey");
            Object o = m.invoke(priv);
            if (o instanceof PublicKey pk) {
                return pk;
            }
        } catch (ReflectiveOperationException ignored) {
            // not a key type that exposes getPublicKey()
        }
        try {
            if (priv instanceof RSAPrivateCrtKey crt) {
                return KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            }
            if (priv instanceof org.bouncycastle.jce.interfaces.ECPrivateKey ec) {
                org.bouncycastle.jce.spec.ECParameterSpec params = ec.getParameters();
                org.bouncycastle.math.ec.ECPoint q = params.getG().multiply(ec.getD()).normalize();
                return KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(q, params));
            }
            // Ed25519: derive the public point from the PKCS#8 seed.
            var lp = org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(priv.getEncoded());
            if (lp instanceof org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters ed) {
                var spki = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
                        .createSubjectPublicKeyInfo(ed.generatePublicKey());
                return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getPublicKey(spki);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}
