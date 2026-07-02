package com.example.csrgen.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A shareable, read-only CSR snapshot for team review. Stores the CSR only —
 * never private keys. Table prefixed per project convention (CLAUDE.md).
 */
@Entity
@Table(name = "csr_studio_share")
public class CsrShare {

    @Id
    @Column(length = 16)
    private String id;

    @Column(name = "csr_pem", columnDefinition = "text", nullable = false)
    private String csrPem;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected CsrShare() {
    }

    public CsrShare(String id, String csrPem, Instant createdAt) {
        this.id = id;
        this.csrPem = csrPem;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getCsrPem() { return csrPem; }
    public Instant getCreatedAt() { return createdAt; }
}
