package com.example.csrgen.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A saved CSR generation. Stores the CSR + metadata only — NEVER the private key
 * (private keys must not be persisted server-side).
 *
 * <p>Table name is prefixed with the app name per project convention (see CLAUDE.md).
 */
@Entity
@Table(name = "csr_studio_csr_history")
public class CsrHistory {

    @Id
    @Column(length = 40)
    private String id;

    @Column(name = "common_name")
    private String commonName;

    private String organization;

    @Column(name = "key_label")
    private String keyLabel;

    @Column(name = "key_detail")
    private String keyDetail;

    @Column(name = "key_format")
    private String keyFormat;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

    /** SANs serialized as a JSON array of {type,value}. */
    @Column(name = "sans_json", columnDefinition = "text")
    private String sansJson;

    @Column(name = "csr_pem", columnDefinition = "text")
    private String csrPem;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected CsrHistory() {
    }

    public CsrHistory(String id, String commonName, String organization, String keyLabel,
                      String keyDetail, String keyFormat, String signatureAlgorithm,
                      String sansJson, String csrPem, Instant createdAt) {
        this.id = id;
        this.commonName = commonName;
        this.organization = organization;
        this.keyLabel = keyLabel;
        this.keyDetail = keyDetail;
        this.keyFormat = keyFormat;
        this.signatureAlgorithm = signatureAlgorithm;
        this.sansJson = sansJson;
        this.csrPem = csrPem;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getCommonName() { return commonName; }
    public String getOrganization() { return organization; }
    public String getKeyLabel() { return keyLabel; }
    public String getKeyDetail() { return keyDetail; }
    public String getKeyFormat() { return keyFormat; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public String getSansJson() { return sansJson; }
    public String getCsrPem() { return csrPem; }
    public Instant getCreatedAt() { return createdAt; }
}
