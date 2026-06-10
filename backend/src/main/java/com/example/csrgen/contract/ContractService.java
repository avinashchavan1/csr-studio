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

    public ContractService(CsrService csrService, CsrParser csrParser, MatchService matchService) {
        this.csrService = csrService;
        this.csrParser = csrParser;
        this.matchService = matchService;
    }

    /* ---------------- generate ---------------- */

    public GenerateResponse generate(GenerateRequest req) {
        ContractKey key = req.key();
        validateAlgorithm(key.algorithm());
        String type = algoType(key.algorithm());   // RSA | ECDSA | ED25519
        boolean ed = type.equals("ED25519");
        boolean ecdsa = type.equals("ECDSA");
        boolean rsa = type.equals("RSA");
        boolean rsaPkcs1 = rsa && "PKCS#1".equalsIgnoreCase(nz(key.format()));
        String hash = StringUtils.hasText(req.signatureHash()) ? req.signatureHash() : "SHA-256";

        List<SanEntryDto> sans = buildSans(req.subject().commonName(), req.subject().email(), req.subjectAltNames());
        if (sans.isEmpty()) {
            throw new CryptoException("Provide a Common Name or at least one Subject Alternative Name.");
        }

        GenerateRequest.Extensions ext = req.extensions();
        CsrRequest internal = new CsrRequest(
                ed ? KeyAlgorithm.ED25519 : ecdsa ? KeyAlgorithm.EC : KeyAlgorithm.RSA,
                rsa ? key.size() : null,
                ecdsa ? key.curve() : null,
                toSubjectDto(req.subject()),
                sans,
                ed ? null : jcaSignatureAlgorithm(hash, ecdsa),   // Ed25519 has a fixed sig scheme
                ext == null ? null : ext.keyUsage(),
                ext == null ? null : ext.extendedKeyUsage());

        GeneratedCsr out = csrService.generateDetailed(internal, rsaPkcs1);

        GenerateResponse.Details details;
        if (ed) {
            details = new GenerateResponse.Details("Ed25519", "Ed25519", "PKCS#8", "Ed25519");
        } else if (ecdsa) {
            details = new GenerateResponse.Details("ECDSA " + key.curve(), key.curve(), "PKCS#8", hash);
        } else {
            details = new GenerateResponse.Details("RSA " + key.size(), key.size() + "-bit",
                    rsaPkcs1 ? "PKCS#1" : "PKCS#8", hash);
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

        DecodeResponse.Key key = new DecodeResponse.Key(
                keyKind(parsed.keyAlgorithm()),
                keyDetail(parsed.keyAlgorithm(), parsed.keySize()),
                parsed.keySize());

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

    /** RSA | ECDSA | ED25519 from the contract algorithm string. */
    private String algoType(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        if (a.equals("ED25519") || a.equals("EDDSA")) {
            return "ED25519";
        }
        if (a.equals("ECDSA") || a.equals("EC")) {
            return "ECDSA";
        }
        return "RSA";
    }

    /** Rejects unknown key algorithms instead of silently falling back to RSA. */
    private void validateAlgorithm(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        if (!a.equals("RSA") && !a.equals("ECDSA") && !a.equals("EC")
                && !a.equals("ED25519") && !a.equals("EDDSA")) {
            throw new CryptoException("Unsupported key algorithm: '" + algorithm + "'. Use RSA, ECDSA or Ed25519.");
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

    private String jcaSignatureAlgorithm(String hash, boolean ecdsa) {
        String h = nz(hash).toUpperCase().replace("-", "");
        if (h.isEmpty()) {
            h = "SHA256";
        }
        return h + "with" + (ecdsa ? "ECDSA" : "RSA");
    }

    private String keyKind(String algo) {
        return switch (nz(algo).toUpperCase()) {
            case "EC", "ECDSA" -> "ECDSA";
            case "ED25519" -> "Ed25519";
            default -> "RSA";
        };
    }

    private String keyDetail(String algo, Integer keySize) {
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
