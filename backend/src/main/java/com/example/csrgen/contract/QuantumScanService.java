package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.QuantumScanRequest;
import com.example.csrgen.contract.dto.QuantumScanResponse;
import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.PemUtil;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Quantum-readiness ("HNDL") assessment of a CSR, certificate, or live TLS endpoint.
 *
 * <p>Classical public-key algorithms (RSA / ECDSA / EdDSA) are breakable by a
 * cryptographically-relevant quantum computer via Shor's algorithm; traffic recorded
 * today can be decrypted later ("harvest now, decrypt later"). NIST PQC algorithms
 * (ML-DSA, SLH-DSA, Falcon) are not.
 */
@Service
public class QuantumScanService {

    private static final Pattern HOST_RE =
            Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251})[a-zA-Z0-9]$");

    private final CsrParser csrParser;

    public QuantumScanService(CsrParser csrParser) {
        this.csrParser = csrParser;
    }

    public QuantumScanResponse scan(QuantumScanRequest req) {
        int provided = (StringUtils.hasText(req.csr()) ? 1 : 0)
                + (StringUtils.hasText(req.certificate()) ? 1 : 0)
                + (StringUtils.hasText(req.host()) ? 1 : 0);
        if (provided != 1) {
            throw new CryptoException("Provide exactly one of: csr, certificate, host.");
        }
        if (StringUtils.hasText(req.csr())) {
            return scanCsr(req.csr());
        }
        if (StringUtils.hasText(req.certificate())) {
            return scanCert(parseCert(req.certificate()), null);
        }
        return scanHost(req.host().trim());
    }

    /* ---------------- inputs ---------------- */

    private QuantumScanResponse scanCsr(String pem) {
        var parsed = csrParser.parse(pem);
        String target = parsed.subjectFields().getOrDefault("commonName",
                parsed.subjectAltNames() != null && !parsed.subjectAltNames().isEmpty()
                        ? parsed.subjectAltNames().get(0).value() : "CSR");
        return grade(target, parsed.keyAlgorithm(), parsed.keySize(),
                parsed.signatureAlgorithm(), null);
    }

    private QuantumScanResponse scanCert(X509Certificate cert, String host) {
        PublicKey pub = cert.getPublicKey();
        String algo = pub.getAlgorithm();
        Integer bits = null;
        if (pub instanceof RSAPublicKey rsa) {
            bits = rsa.getModulus().bitLength();
        } else if (pub instanceof ECPublicKey ec) {
            bits = ec.getParams().getCurve().getField().getFieldSize();
        }
        String target = host != null ? host : cert.getSubjectX500Principal().getName();
        QuantumScanResponse base = grade(target, algo, bits, cert.getSigAlgName(),
                cert.getNotAfter().toInstant().toString());
        return base;
    }

    private QuantumScanResponse scanHost(String host) {
        if (!HOST_RE.matcher(host).matches() || host.contains("/")) {
            throw new CryptoException("Invalid hostname: " + host);
        }
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            // Trust-all on purpose: we only READ the presented certificate to assess it;
            // nothing sensitive is transmitted over this probe connection.
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) { }
                public void checkServerTrusted(X509Certificate[] c, String a) { }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                s.connect(new java.net.InetSocketAddress(host, 443), 7000);
                s.setSoTimeout(7000);
                s.startHandshake();
                Certificate[] chain = s.getSession().getPeerCertificates();
                if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                    throw new CryptoException("No X.509 certificate presented by " + host);
                }
                return scanCert(leaf, host);
            }
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Could not fetch the TLS certificate from " + host
                    + ": " + e.getMessage());
        }
    }

    private X509Certificate parseCert(String pem) {
        try {
            byte[] der = PemUtil.pemToDer(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CryptoException("Invalid certificate PEM: " + e.getMessage());
        }
    }

    /* ---------------- grading ---------------- */

    private QuantumScanResponse grade(String target, String keyAlgo, Integer bits,
                                      String sigAlgo, String notAfter) {
        String a = keyAlgo == null ? "" : keyAlgo.toUpperCase();
        boolean pqc = a.startsWith("ML-DSA") || a.startsWith("SLH-DSA") || a.startsWith("FALCON")
                || a.startsWith("MLDSA") || a.startsWith("DILITHIUM");
        List<String> findings = new ArrayList<>();
        String grade;
        int score;
        String hndl;
        String rec;

        String sigU = sigAlgo == null ? "" : sigAlgo.toUpperCase();
        boolean weakHash = sigU.contains("SHA1") || sigU.contains("MD5");

        if (pqc) {
            grade = "A+"; score = 5; hndl = "none";
            findings.add(keyAlgo + " is a NIST post-quantum algorithm — not breakable by Shor's algorithm.");
            rec = "Already quantum-safe. Pair with a classical certificate (hybrid) until CAs/browsers accept PQC broadly.";
        } else {
            boolean rsa = a.contains("RSA");
            boolean ec = a.contains("EC") || a.contains("ED25519");
            findings.add((keyAlgo == null ? "Unknown key" : keyAlgo)
                    + (bits != null ? " " + bits + "-bit" : "")
                    + " is breakable by a cryptographically-relevant quantum computer (Shor's algorithm).");
            if (rsa && bits != null && bits < 2048) {
                grade = "F"; score = 100; hndl = "high";
                findings.add("Key is below today's classical minimum (2048) — weak even pre-quantum.");
            } else if (weakHash) {
                grade = "F"; score = 95; hndl = "high";
            } else if (rsa && bits != null && bits >= 3072) {
                grade = "C"; score = 60; hndl = "medium";
            } else if (ec) {
                grade = "D"; score = 75; hndl = "medium";
                findings.add("Elliptic-curve keys need fewer quantum resources to break than RSA-2048 — they fall first.");
            } else {
                grade = "D"; score = 70; hndl = "medium";
            }
            findings.add("HNDL: traffic recorded today can be decrypted retroactively once quantum computers mature.");
            rec = "Plan migration to ML-DSA (FIPS 204). Generate a hybrid pair now — classical for today's CAs, ML-DSA-65 for crypto-agility — via the Hybrid generator.";
        }
        if (weakHash) {
            findings.add("Signature uses a broken hash (" + sigAlgo + ") — replace immediately, quantum aside.");
        }
        if (notAfter != null) {
            findings.add("Certificate expires " + notAfter + ".");
        }
        return new QuantumScanResponse(target, keyAlgo,
                bits != null ? bits + "-bit" : "", sigAlgo, !pqc, grade, score, hndl,
                findings, rec, notAfter);
    }
}
