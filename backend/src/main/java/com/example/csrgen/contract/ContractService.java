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

import java.util.List;
import java.util.Map;

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
        boolean ecdsa = isEcdsa(key.algorithm());
        boolean rsaPkcs1 = !ecdsa && "PKCS#1".equalsIgnoreCase(nz(key.format()));
        String hash = StringUtils.hasText(req.signatureHash()) ? req.signatureHash() : "SHA-256";

        CsrRequest internal = new CsrRequest(
                ecdsa ? KeyAlgorithm.EC : KeyAlgorithm.RSA,
                ecdsa ? null : key.size(),
                ecdsa ? key.curve() : null,
                toSubjectDto(req.subject()),
                toSanDtos(req.subjectAltNames()),
                jcaSignatureAlgorithm(hash, ecdsa));

        GeneratedCsr out = csrService.generateDetailed(internal, rsaPkcs1);

        GenerateResponse.Details details = ecdsa
                ? new GenerateResponse.Details("ECDSA " + key.curve(), key.curve(), "PKCS#8", hash)
                : new GenerateResponse.Details("RSA " + key.size(), key.size() + "-bit",
                        rsaPkcs1 ? "PKCS#1" : "PKCS#8", hash);

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
                parsed.signatureAlgorithm(), parsed.signatureValid());

        return new DecodeResponse(subject, sans, key, sig);
    }

    /* ---------------- match ---------------- */

    public MatchResponse match(String csrPem, String keyPem) {
        MatchService.Result r = matchService.match(csrPem, keyPem);
        return new MatchResponse(r.supported(), r.match(), r.bits());
    }

    /* ---------------- mapping helpers ---------------- */

    private boolean isEcdsa(String algorithm) {
        String a = nz(algorithm).toUpperCase();
        return a.equals("ECDSA") || a.equals("EC");
    }

    private SubjectDto toSubjectDto(ContractSubject s) {
        if (s == null) {
            throw new CryptoException("subject is required");
        }
        return new SubjectDto(
                s.commonName(), s.organization(), s.organizationalUnit(),
                s.locality(), s.state(), s.country(), s.email());
    }

    private List<SanEntryDto> toSanDtos(List<ContractSan> sans) {
        if (sans == null) {
            return List.of();
        }
        return sans.stream().map(s -> {
            SanType type;
            try {
                type = SanType.valueOf(nz(s.type()).toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new CryptoException("Unsupported SAN type: " + s.type());
            }
            return new SanEntryDto(type, s.value());
        }).toList();
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

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
