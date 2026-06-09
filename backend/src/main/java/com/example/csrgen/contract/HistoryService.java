package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.ContractSan;
import com.example.csrgen.contract.dto.HistoryRecord;
import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.persistence.CsrHistory;
import com.example.csrgen.persistence.CsrHistoryRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Persists CSR generation history (metadata + CSR PEM only — no private keys).
 */
@Service
public class HistoryService {

    private final CsrHistoryRepository repo;
    private final ObjectMapper mapper;

    public HistoryService(CsrHistoryRepository repo, ObjectMapper mapper) {
        this.repo = repo;
        this.mapper = mapper;
    }

    @Transactional
    public HistoryRecord save(HistoryRecord req) {
        String sansJson = writeSans(req.sans());
        CsrHistory entity = new CsrHistory(
                UUID.randomUUID().toString(),
                req.commonName(), req.organization(), req.keyLabel(), req.keyDetail(),
                req.keyFormat(), req.signatureAlgorithm(), sansJson, req.csrPem(), Instant.now());
        return toDto(repo.save(entity));
    }

    @Transactional(readOnly = true)
    public List<HistoryRecord> list() {
        return repo.findTop40ByOrderByCreatedAtDesc().stream().map(this::toDto).toList();
    }

    @Transactional
    public void delete(String id) {
        repo.deleteById(id);
    }

    @Transactional
    public void clear() {
        repo.deleteAll();
    }

    private HistoryRecord toDto(CsrHistory e) {
        return new HistoryRecord(
                e.getId(), e.getCommonName(), e.getOrganization(), e.getKeyLabel(),
                e.getKeyDetail(), e.getKeyFormat(), e.getSignatureAlgorithm(),
                readSans(e.getSansJson()), e.getCsrPem(), e.getCreatedAt().toEpochMilli());
    }

    private String writeSans(List<ContractSan> sans) {
        try {
            return mapper.writeValueAsString(sans == null ? List.of() : sans);
        } catch (Exception e) {
            throw new CryptoException("Could not serialize SANs: " + e.getMessage(), e);
        }
    }

    private List<ContractSan> readSans(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return mapper.readValue(json, new TypeReference<List<ContractSan>>() {});
        } catch (Exception e) {
            return List.of();
        }
    }
}
