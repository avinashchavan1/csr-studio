package com.example.csrgen.contract;

import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.CsrParseResponse;
import com.example.csrgen.api.dto.SanEntryDto;
import com.example.csrgen.api.dto.SubjectDto;
import com.example.csrgen.contract.dto.ContractKey;
import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.ContractSubject;
import com.example.csrgen.contract.dto.DecodeResponse;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.contract.dto.MatchResponse;
import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.GeneratedCsr;
import com.example.csrgen.crypto.MatchService;
import com.example.csrgen.domain.KeyAlgorithm;
import com.example.csrgen.domain.SanType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Bridges the CSR Studio API contract to the internal crypto services:
 * maps contract DTOs to/from the engine and assembles the response shapes the UI expects.
 */
@Service
public class ContractService {

    private final CsrService csrService;
    private final CsrParser csrParser;
    private final MatchService matchService;
    private final com.example.csrgen.crypto.CertService certService;

    public ContractService(CsrService csrService, CsrParser csrParser, MatchService matchService,
                           com.example.csrgen.crypto.CertService certService) {
        this.csrService = csrService;
        this.csrParser = csrParser;
        this.matchService = matchService;
        this.certService = certService;
    }

    /**
     * Hybrid generation: one identity, two CSRs — the request's classical key spec plus a
     * PQC parameter set. Same subject / SANs / extensions in both, independent key pairs.
     */
    public com.example.csrgen.contract.dto.HybridResponse hybrid(GenerateRequest req, String pqcAlgo) {
        String type = algoType(req.key().algorithm());
        if (type.equals("PQC")) {
            throw new CryptoException("Hybrid needs a classical key (RSA/ECDSA/Ed25519) in the request; the PQC half comes from the 'pqc' parameter.");
        }
        if (canonicalPqcName(pqcAlgo == null ? "" : pqcAlgo) == null) {
            throw new CryptoException("Unknown PQC parameter set: '" + pqcAlgo + "'. Use ML-DSA / SLH-DSA / Falcon names.");
        }
        GenerateResponse classical = generate(req);
        GenerateRequest pqcReq = new GenerateRequest(
                req.subject(), req.subjectAltNames(),
                new ContractKey(pqcAlgo, null, null, "PKCS#8"),
                req.signatureHash(), req.extensions());
        GenerateResponse pqc = generate(pqcReq);
        return new com.example.csrgen.contract.dto.HybridResponse(classical, pqc);
    }

    /** Generate a CSR, then self-sign a test certificate from it. */
    public com.example.csrgen.contract.dto.SelfSignedResponse selfSigned(GenerateRequest req, int days) {
        GenerateResponse gen = generate(req);
        String cert = certService.selfSign(gen.csr(), gen.privateKey(), days);
        return new com.example.csrgen.contract.dto.SelfSignedResponse(
                cert, gen.privateKey(), gen.csr(), gen.details());
    }

    /* ---------------- generate ---------------- */

    public GenerateResponse generate(GenerateRequest req) {
        ContractKey key = req.key();
        validateAlgorithm(key.algorithm());
        String type = algoType(key.algorithm());   // RSA | ECDSA | ED25519 | PQC
        boolean pqc = type.equals("PQC");
        boolean ed = type.equals("ED25519");
        boolean ecdsa = type.equals("ECDSA");
        boolean rsa = type.equals("RSA");
        boolean rsaPkcs1 = rsa && "PKCS#1".equalsIgnoreCase(nz(key.format()));
        String hash = StringUtils.hasText(req.signatureHash()) ? req.signatureHash() : "SHA-256";

        List<SanEntryDto> sans = buildSans(req.subject().commonName(), req.subject().email(), req.subjectAltNames());
        if (sans.isEmpty()) {
            throw new CryptoException("Provide a Common Name or at least one Subject Alternative Name.");
        }

        // For PQC the signature algorithm IS the parameter-set name (e.g. "ML-DSA-65").
        String pqcName = pqc ? canonicalPqcName(key.algorithm()) : null;
        boolean pss = rsa && Boolean.TRUE.equals(key.rsaPss());
        String sigAlg = pqc ? pqcName
                : ed ? null
                : ecdsa ? jcaSignatureAlgorithm(hash, true)
                : pss ? jcaPssAlgorithm(hash)
                : jcaSignatureAlgorithm(hash, false);

        GenerateRequest.Extensions ext = req.extensions();
        CsrRequest internal = new CsrRequest(
                pqc ? pqcEnum(key.algorithm()) : ed ? KeyAlgorithm.ED25519 : ecdsa ? KeyAlgorithm.EC : KeyAlgorithm.RSA,
                rsa ? key.size() : null,
                pqc ? pqcName : ecdsa ? key.curve() : null,   // ecCurve slot carries the PQC param set
                toSubjectDto(req.subject()),
                sans,
                sigAlg,
                ext == null ? null : ext.keyUsage(),
                ext == null ? null : ext.extendedKeyUsage(),
                ext == null ? null : ext.basicConstraintsCa(),
                ext == null ? null : ext.basicConstraintsPathLen());

        GeneratedCsr out = csrService.generateDetailed(internal, rsaPkcs1);

        GenerateResponse.Details details;
        if (pqc) {
            details = new GenerateResponse.Details(pqcName, pqcFamily(pqcName), "PKCS#8", pqcName);
        } else if (ed) {
            details = new GenerateResponse.Details("Ed25519", "Ed25519", "PKCS#8", "Ed25519");
        } else if (ecdsa) {
            details = new GenerateResponse.Details("ECDSA " + key.curve(), key.curve(), "PKCS#8", hash);
        } else {
            details = new GenerateResponse.Details("RSA " + key.size(), key.size() + "-bit",
                    rsaPkcs1 ? "PKCS#1" : "PKCS#8", pss ? hash + " (RSA-PSS)" : hash);
        }
        return new GenerateResponse(out.csrPem(), out.keyPem(), details);
    }

    /* ---------------- decode ---------------- */

    public DecodeResponse decode(String csrPem) {
        CsrParseResponse parsed = csrParser.parse(csrPem);
        Map<String, String> f = parsed.subjectFields();

        ContractSubject subject = new ContractSubject(
                f.getOrDefault("commonName", ""),
                f.getOrDefault("organization", ""),
                f.getOrDefault("organizationalUnit", ""),
                f.getOrDefault("locality", ""),
                f.getOrDefault("state", ""),
                f.getOrDefault("country", ""),
                f.getOrDefault("email", ""));

        List<ContractSan> sans = parsed.subjectAltNames() == null ? List.of()
                : parsed.subjectAltNames().stream()
                        .map(s -> new ContractSan(s.type().name(), s.value()))
                        .toList();

        CsrParser.Fingerprint fp = csrParser.publicKeyFingerprint(csrParser.decode(csrPem));
        DecodeResponse.Key key = new DecodeResponse.Key(
                keyKind(parsed.keyAlgorithm()),
                keyDetail(parsed.keyAlgorithm(), parsed.keySize()),
                parsed.keySize(), fp.sha256(), fp.pin());

        DecodeResponse.Signature sig = new DecodeResponse.Signature(
                prettySig(parsed.signatureAlgorithm()), parsed.signatureValid());

        DecodeResponse.Extensions exts = (parsed.keyUsages() == null
                && parsed.extendedKeyUsages() == null && parsed.basicConstraints() == null)
                ? null
                : new DecodeResponse.Extensions(
                        parsed.keyUsages(), parsed.extendedKeyUsages(), parsed.basicConstraints());

        return new DecodeResponse(subject, sans, key, sig, exts);
    }

    /* ---------------- match ---------------- */

    public MatchResponse match(String csrPem, String keyPem) {
        MatchService.Result r = matchService.match(csrPem, keyPem);
        return new MatchResponse(r.supported(), r.match(), r.bits());
    }

    /* ---------------- mapping helpers ---------------- */

    private static final Pattern DNS_RE = Pattern.compile(
            "^(\\*\\.)?([a-zA-Z0-9_](-?[a-zA-Z0-9_])*)(\\.[a-zA-Z0-9_](-?[a-zA-Z0-9_])*)*$");
    private static final Pattern IPV4_RE = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$");

    /** Post-quantum parameter sets we expose, keyed by upper-case name → canonical BC name. */
    private static final Map<String, String> PQC_CANON = Map.ofEntries(
            Map.entry("ML-DSA-44", "ML-DSA-44"),
            Map.entry("ML-DSA-65", "ML-DSA-65"),
            Map.entry("ML-DSA-87", "ML-DSA-87"),
            Map.entry("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S"),
            Map.entry("SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192S"),
            Map.entry("SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256S"),
            Map.entry("FALCON-512", "Falcon-512"),
            Map.entry("FALCON-1024", "Falcon-1024"));

    /** RSA | ECDSA | ED25519 | PQC from the contract algorithm string. */
    private String algoType(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        if (PQC_CANON.containsKey(a)) {
            return "PQC";
        }
        if (a.equals("ED25519") || a.equals("EDDSA")) {
            return "ED25519";
        }
        if (a.equals("ECDSA") || a.equals("EC")) {
            return "ECDSA";
        }
        return "RSA";
    }

    private String canonicalPqcName(String algorithm) {
        return PQC_CANON.get(nz(algorithm).toUpperCase());
    }

    private KeyAlgorithm pqcEnum(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        if (a.startsWith("ML-DSA")) {
            return KeyAlgorithm.ML_DSA;
        }
        if (a.startsWith("SLH-DSA")) {
            return KeyAlgorithm.SLH_DSA;
        }
        return KeyAlgorithm.FALCON;
    }

    private String pqcFamily(String name) {
        String a = nz(name).toUpperCase();
        if (a.startsWith("ML-DSA")) {
            return "ML-DSA · FIPS 204 (post-quantum)";
        }
        if (a.startsWith("SLH-DSA")) {
            return "SLH-DSA · FIPS 205 (post-quantum)";
        }
        return "Falcon (post-quantum)";
    }

    /** Rejects unknown key algorithms instead of silently falling back to RSA. */
    private void validateAlgorithm(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        if (PQC_CANON.containsKey(a)) {
            return;
        }
        if (!a.equals("RSA") && !a.equals("ECDSA") && !a.equals("EC")
                && !a.equals("ED25519") && !a.equals("EDDSA")) {
            throw new CryptoException("Unsupported key algorithm: '" + algorithm
                    + "'. Use RSA, ECDSA, Ed25519, or a PQC algorithm (ML-DSA / SLH-DSA / Falcon).");
        }
    }

    private boolean isIpv4(String v) {
        return IPV4_RE.matcher(v).matches();
    }

    private boolean isIp(String v) {
        return isIpv4(v) || (v.contains(":") && v.matches("^[0-9a-fA-F:]+$"));
    }

    /**
     * Builds the SAN list: validates each entry, dedupes, and ensures the CN is
     * present as a SAN (CA/Browser Forum + RFC 6125 require it — browsers ignore CN).
     */
    private static final int MAX_SANS = 100;

    private List<SanEntryDto> buildSans(String commonName, String email, List<ContractSan> sans) {
        LinkedHashMap<String, SanEntryDto> out = new LinkedHashMap<>();

        String cn = nz(commonName).trim();
        if (!cn.isEmpty()) {
            SanType cnType = isIp(cn) ? SanType.IP : SanType.DNS;
            addSan(out, cnType, cn);
        }
        if (sans != null) {
            for (ContractSan s : sans) {
                SanType type;
                try {
                    type = SanType.valueOf(nz(s.type()).toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new CryptoException("Unsupported SAN type: " + s.type());
                }
                String v = nz(s.value()).trim();
                validateSan(type, v);
                addSan(out, type, v);
            }
        }
        // Subject email belongs in SAN as rfc822Name (deprecated in the DN for TLS).
        String em = nz(email).trim();
        if (!em.isEmpty()) {
            addSan(out, SanType.EMAIL, em);
        }
        if (out.size() > MAX_SANS) {
            throw new CryptoException("Too many Subject Alternative Names (max " + MAX_SANS + ").");
        }
        return new ArrayList<>(out.values());
    }

    private void addSan(LinkedHashMap<String, SanEntryDto> out, SanType type, String value) {
        if (value.isEmpty()) {
            return;
        }
        out.putIfAbsent(type.name() + "|" + value.toLowerCase(), new SanEntryDto(type, value));
    }

    private void validateSan(SanType type, String value) {
        if (value.isEmpty()) {
            throw new CryptoException("SAN value cannot be empty.");
        }
        switch (type) {
            case IP -> {
                if (!isIp(value)) {
                    throw new CryptoException("Invalid IP address in SAN: " + value);
                }
            }
            case DNS -> {
                if (value.length() > 253 || !DNS_RE.matcher(value).matches()) {
                    throw new CryptoException("Invalid DNS name in SAN: " + value);
                }
            }
            default -> {
                // EMAIL / URI accepted as-is
            }
        }
    }

    private SubjectDto toSubjectDto(ContractSubject s) {
        if (s == null) {
            throw new CryptoException("subject is required");
        }
        return new SubjectDto(
                s.commonName(), s.organization(), s.organizationalUnit(),
                s.locality(), s.state(), s.country(), s.email());
    }

    /** RSASSA-PSS signature algorithm name for Bouncy Castle (e.g. SHA256withRSAandMGF1). */
    private String jcaPssAlgorithm(String hash) {
        String h = nz(hash).toUpperCase().replace("-", "");
        if (h.isEmpty()) {
            h = "SHA256";
        }
        return h + "withRSAandMGF1";
    }

    private String jcaSignatureAlgorithm(String hash, boolean ecdsa) {
        String h = nz(hash).toUpperCase().replace("-", "");
        if (h.isEmpty()) {
            h = "SHA256";
        }
        return h + "with" + (ecdsa ? "ECDSA" : "RSA");
    }

    private String keyKind(String algo) {
        String u = nz(algo).toUpperCase();
        if (u.startsWith("ML-DSA") || u.startsWith("SLH-DSA") || u.startsWith("FALCON")) {
            return algo;   // PQC — report the parameter-set name directly
        }
        return switch (u) {
            case "EC", "ECDSA" -> "ECDSA";
            case "ED25519" -> "Ed25519";
            default -> "RSA";
        };
    }

    private String keyDetail(String algo, Integer keySize) {
        String u0 = nz(algo).toUpperCase();
        if (u0.startsWith("ML-DSA") || u0.startsWith("SLH-DSA") || u0.startsWith("FALCON")) {
            return pqcFamily(algo);
        }
        if (keySize == null) {
            return "";
        }
        String a = nz(algo).toUpperCase();
        if (a.equals("EC") || a.equals("ECDSA")) {
            return switch (keySize) {
                case 256 -> "P-256";
                case 384 -> "P-384";
                case 521 -> "P-521";
                default -> keySize + "-bit";
            };
        }
        if (a.equals("ED25519")) {
            return "Ed25519";
        }
        return keySize + "-bit";
    }

    /** "SHA256WITHRSA" → "SHA256withRSA" (BouncyCastle returns all-caps). */
    private String prettySig(String algo) {
        return algo == null ? null : algo.replace("WITH", "with");
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
