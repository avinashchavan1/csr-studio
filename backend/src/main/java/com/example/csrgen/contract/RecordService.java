package com.example.csrgen.contract;

import com.example.csrgen.persistence.CsrRecord;
import com.example.csrgen.persistence.CsrRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persists a retrievable snapshot of a generated CSR under a UUID, served at
 * {@code /r/<id>}. Stores the CSR + a short key label only — never private keys.
 */
@Service
public class RecordService {

    private static final Logger log = LoggerFactory.getLogger(RecordService.class);

    /** Cap on stored records; oldest are trimmed beyond this (bounded storage). */
    private static final long MAX_ROWS = 10_000;

    private final CsrRecordRepository repo;

    public RecordService(CsrRecordRepository repo) {
        this.repo = repo;
    }

    /**
     * Saves a CSR snapshot and returns its UUID. Never throws — if persistence is
     * unavailable, returns {@code null} so generation itself is never blocked.
     */
    public String save(String csrPem, String keyLabel) {
        if (csrPem == null || csrPem.isBlank()) {
            return null;
        }
        try {
            String id = UUID.randomUUID().toString();
            repo.save(new CsrRecord(id, csrPem, keyLabel, Instant.now()));
            trim();
            return id;
        } catch (Exception e) {
            log.warn("Could not persist CSR record (generation continues): {}", e.getMessage());
            return null;
        }
    }

    public Optional<CsrRecord> get(String id) {
        try {
            return repo.findById(id);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private void trim() {
        try {
            long count = repo.count();
            if (count > MAX_ROWS) {
                repo.deleteAll(repo.findByOrderByCreatedAtAsc(
                        PageRequest.of(0, (int) Math.min(count - MAX_ROWS, 1000))));
            }
        } catch (Exception ignored) {
            // best-effort housekeeping
        }
    }
}
