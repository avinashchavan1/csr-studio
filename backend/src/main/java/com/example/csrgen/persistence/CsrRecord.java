package com.example.csrgen.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A persisted, retrievable snapshot of a generated CSR, addressable by a UUID
 * (served at {@code /r/<id>}). Stores the CSR + metadata only — <strong>never the
 * private key</strong>. Table prefixed per project convention (CLAUDE.md).
 */
@Entity
@Table(name = "csr_studio_record")
public class CsrRecord {

    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "csr_pem", columnDefinition = "text", nullable = false)
    private String csrPem;

    /** Short human label for the key (e.g. "RSA 2048", "ML-DSA-65"). Metadata only. */
    @Column(name = "key_label", length = 64)
    private String keyLabel;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected CsrRecord() {
    }

    public CsrRecord(String id, String csrPem, String keyLabel, Instant createdAt) {
        this.id = id;
        this.csrPem = csrPem;
        this.keyLabel = keyLabel;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getCsrPem() { return csrPem; }
    public String getKeyLabel() { return keyLabel; }
    public Instant getCreatedAt() { return createdAt; }
}
