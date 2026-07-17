package com.example.csrgen.crypto;

import com.example.csrgen.contract.dto.ChainRequest;
import com.example.csrgen.contract.dto.ChainResponse;
import com.example.csrgen.contract.dto.ChainResponse.ChainCert;
import com.example.csrgen.contract.dto.ChainResponse.ChainLink;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Builds and validates a certificate chain from a pasted bundle: orders the
 * certs leaf → root, verifies every link's signature (classical + PQC via
 * Bouncy Castle), checks validity windows, CA flags and key usages, and
 * reports what's missing when the chain is incomplete.
 */
@Service
public class ChainService {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);
    private static final DefaultAlgorithmNameFinder ALGO_FINDER = new DefaultAlgorithmNameFinder();
    private static final int MAX_CHAIN = 12;

    public ChainResponse analyze(ChainRequest req) {
        String input = req == null ? null : req.certificates();
        if (input == null || input.isBlank()) {
            throw new CryptoException("Paste one or more PEM certificates to analyse.");
        }
        List<X509Certificate> pool = parseCertificates(input.trim());
        List<String> warnings = new ArrayList<>();

        // ---- pick the leaf: a cert that doesn't issue any other cert in the set ----
        List<X509Certificate> leaves = new ArrayList<>();
        for (X509Certificate c : pool) {
            boolean issuesAnother = pool.stream().anyMatch(o -> o != c
                    && o.getIssuerX500Principal().equals(c.getSubjectX500Principal()));
            if (!issuesAnother) {
                leaves.add(c);
            }
        }
        X509Certificate leaf;
        if (leaves.isEmpty()) {
            leaf = pool.get(0); // cross-signed loop — start somewhere sensible
            warnings.add("Every certificate issues another one (a cross-signed loop?) — "
                    + "starting the chain from the first certificate pasted.");
        } else {
            // prefer an end-entity (CA:FALSE) leaf when several candidates exist
            leaf = leaves.stream().filter(c -> c.getBasicConstraints() < 0)
                    .findFirst().orElse(leaves.get(0));
            if (leaves.size() > 1) {
                warnings.add("Found " + leaves.size() + " possible leaf certificates — using \""
                        + cn(leaf) + "\". The others are listed under 'not part of this chain'.");
            }
        }

        // ---- walk leaf → root ----
        List<X509Certificate> ordered = new ArrayList<>();
        List<X509Certificate> remaining = new ArrayList<>(pool);
        X509Certificate current = leaf;
        ordered.add(current);
        remaining.remove(current);
        boolean complete = isSelfSigned(current);
        String missingIssuer = null;
        String missingIssuerUrl = null;
        while (!complete && ordered.size() < MAX_CHAIN) {
            final X509Certificate child = current;
            X509Certificate parent = remaining.stream()
                    .filter(p -> p.getSubjectX500Principal().equals(child.getIssuerX500Principal()))
                    .filter(p -> signatureValid(child, p.getPublicKey()))
                    .findFirst()
                    .orElseGet(() -> remaining.stream()   // name matches even if the signature fails
                            .filter(p -> p.getSubjectX500Principal().equals(child.getIssuerX500Principal()))
                            .findFirst().orElse(null));
            if (parent == null) {
                missingIssuer = child.getIssuerX500Principal().toString();
                missingIssuerUrl = caIssuersUrl(child);
                break;
            }
            ordered.add(parent);
            remaining.remove(parent);
            current = parent;
            complete = isSelfSigned(current);
        }
        if (ordered.size() >= MAX_CHAIN && !complete) {
            warnings.add("Stopped after " + MAX_CHAIN + " certificates — the chain looks cyclic.");
        }

        // ---- describe certs + check links ----
        List<ChainCert> chain = new ArrayList<>();
        for (int i = 0; i < ordered.size(); i++) {
            chain.add(describe(i, ordered.get(i)));
        }
        List<ChainLink> links = new ArrayList<>();
        boolean linksOk = true;
        for (int i = 0; i < ordered.size() - 1; i++) {
            X509Certificate child = ordered.get(i);
            X509Certificate parent = ordered.get(i + 1);
            boolean sig = signatureValid(child, parent.getPublicKey());
            boolean isCa = parent.getBasicConstraints() >= 0;
            boolean canSign = canSignCerts(parent);
            boolean names = parent.getSubjectX500Principal().equals(child.getIssuerX500Principal());
            links.add(new ChainLink(i, i + 1, sig, isCa, canSign, names));
            linksOk &= sig && isCa && canSign && names;
        }
        X509Certificate root = ordered.get(ordered.size() - 1);
        if (complete && !signatureValid(root, root.getPublicKey())) {
            warnings.add("The root certificate's self-signature doesn't verify — it may be corrupted.");
        }
        boolean timesOk = chain.stream().noneMatch(c -> c.expired() || c.notYetValid());
        if (!timesOk) {
            warnings.add("At least one certificate is outside its validity window.");
        }
        if (!complete && missingIssuer != null) {
            warnings.add("The chain is incomplete — missing the issuer \"" + missingIssuer + "\"."
                    + (missingIssuerUrl != null ? " Its certificate may be downloadable from the AIA URL." : ""));
        }

        List<ChainCert> extras = new ArrayList<>();
        for (X509Certificate c : remaining) {
            extras.add(describe(-1, c));
        }
        if (!extras.isEmpty()) {
            warnings.add(extras.size() + " pasted certificate(s) aren't part of this chain.");
        }

        StringBuilder pem = new StringBuilder();
        for (X509Certificate c : ordered) {
            pem.append(PemUtil.toPem(c));
        }

        return new ChainResponse(chain, links, complete,
                complete && linksOk && timesOk,
                missingIssuer, missingIssuerUrl,
                extras.isEmpty() ? null : extras,
                warnings.isEmpty() ? null : warnings,
                pem.toString());
    }

    /* ---------------- parsing ---------------- */

    private List<X509Certificate> parseCertificates(String input) {
        JcaX509CertificateConverter conv =
                new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        List<X509Certificate> out = new ArrayList<>();
        if (input.contains("-----BEGIN")) {
            if (input.toUpperCase().contains("PRIVATE KEY")) {
                throw new CryptoException("That includes a PRIVATE KEY — never paste private keys here. "
                        + "This tool only needs the certificates.");
            }
            try (PEMParser parser = new PEMParser(new StringReader(input))) {
                Object obj;
                while ((obj = parser.readObject()) != null) {
                    if (obj instanceof X509CertificateHolder h) {
                        out.add(conv.getCertificate(h));
                    }
                }
            } catch (Exception e) {
                throw new CryptoException("Couldn't read the certificates. Check that every "
                        + "-----BEGIN CERTIFICATE----- block is complete and nothing is truncated.");
            }
        } else {
            // bare base64 → a single DER certificate
            try {
                out.add(conv.getCertificate(new X509CertificateHolder(PemUtil.pemToDer(input))));
            } catch (Exception e) {
                throw new CryptoException("That input isn't a PEM certificate bundle or a bare "
                        + "base64 certificate. Paste the chain as -----BEGIN CERTIFICATE----- blocks.");
            }
        }
        if (out.isEmpty()) {
            throw new CryptoException("No certificates found in that input. Paste one or more "
                    + "-----BEGIN CERTIFICATE----- blocks (a CSR is not a certificate).");
        }
        // dedupe identical certs
        List<X509Certificate> unique = new ArrayList<>();
        for (X509Certificate c : out) {
            boolean dup = unique.stream().anyMatch(u -> {
                try {
                    return MessageDigest.isEqual(u.getEncoded(), c.getEncoded());
                } catch (Exception e) {
                    return false;
                }
            });
            if (!dup) {
                unique.add(c);
            }
        }
        return unique;
    }

    /* ---------------- checks + description ---------------- */

    private boolean signatureValid(X509Certificate cert, PublicKey issuerKey) {
        try {
            cert.verify(issuerKey, BouncyCastleProvider.PROVIDER_NAME);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isSelfSigned(X509Certificate c) {
        return c.getSubjectX500Principal().equals(c.getIssuerX500Principal())
                && signatureValid(c, c.getPublicKey());
    }

    /** keyCertSign present, or no keyUsage extension at all (then anything goes). */
    private boolean canSignCerts(X509Certificate c) {
        boolean[] ku = c.getKeyUsage();
        return ku == null || (ku.length > 5 && ku[5]);
    }

    private String caIssuersUrl(X509Certificate c) {
        try {
            byte[] ext = c.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (ext == null) {
                return null;
            }
            var holder = new X509CertificateHolder(c.getEncoded());
            AuthorityInformationAccess aia = AuthorityInformationAccess.fromExtensions(
                    holder.toASN1Structure().getTBSCertificate().getExtensions());
            if (aia == null) {
                return null;
            }
            for (AccessDescription d : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_caIssuers.equals(d.getAccessMethod())
                        && d.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return d.getAccessLocation().getName().toString();
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private ChainCert describe(int index, X509Certificate c) {
        Date now = new Date();
        PublicKey pub = c.getPublicKey();
        String kind = SignatureSupport.keyKind(pub);
        String sigAlgo;
        try {
            sigAlgo = ALGO_FINDER.getAlgorithmName(
                    new X509CertificateHolder(c.getEncoded()).getSignatureAlgorithm());
        } catch (Exception e) {
            sigAlgo = c.getSigAlgName();
        }
        int bc = c.getBasicConstraints();
        return new ChainCert(index,
                c.getSubjectX500Principal().toString(),
                c.getIssuerX500Principal().toString(),
                c.getSerialNumber().toString(16),
                TS.format(Instant.ofEpochMilli(c.getNotBefore().getTime())),
                TS.format(Instant.ofEpochMilli(c.getNotAfter().getTime())),
                now.after(c.getNotAfter()),
                now.before(c.getNotBefore()),
                isSelfSigned(c),
                bc >= 0,
                bc >= 0 && bc != Integer.MAX_VALUE ? bc : null,
                kind,
                keyDetail(kind, pub),
                SignatureSupport.isPqc(kind),
                sigAlgo,
                certSha256(c));
    }

    private String keyDetail(String kind, PublicKey pub) {
        if (pub instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() + "-bit";
        }
        if (kind.equals("EC") && pub instanceof java.security.interfaces.ECPublicKey ec) {
            int size = ec.getParams().getCurve().getField().getFieldSize();
            return "P-" + size;
        }
        return pub.getAlgorithm();
    }

    private String certSha256(X509Certificate c) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : h) {
                if (sb.length() > 0) {
                    sb.append(':');
                }
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String cn(X509Certificate c) {
        String dn = c.getSubjectX500Principal().toString();
        var m = java.util.regex.Pattern.compile("CN=([^,]+)").matcher(dn);
        return m.find() ? m.group(1) : dn;
    }
}
