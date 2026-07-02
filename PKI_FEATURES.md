# CSR Studio — PKI feature roadmap (expert review)

Audit of fields/capabilities vs PKI best practice, with phased implementation.

## Findings
- **Ed25519 (EdDSA)** key type absent from API/UI (backend already supports it). Modern, fast.
- **Decode** doesn't surface requested extensions (keyUsage/EKU/basicConstraints) — round-trip incomplete.
- **Country** accepts lowercase; X.520 expects uppercase 2-letter.
- **CN required**; modern practice allows SAN-only (CN optional, SAN mandatory).
- UI can only add **DNS/IP** SANs; `email`/`URI` SAN types unsupported in UI.
- **basicConstraints** (CA:true/pathlen) not requestable.
- No **self-signed test cert**, no **RSA-PSS**, PKCS#12 not wired to UI.

## Phases
### Phase 1 — correctness + round-trip  ← implementing
- F1 Ed25519 (EdDSA) key type (contract + UI).
- F2 Decode displays requested extensions (keyUsage, extendedKeyUsage, basicConstraints).
- F3 Country uppercased; allow SAN-only CSR (CN optional, require CN or ≥1 SAN).

### Phase 2 — extension/SAN completeness
- F4 basicConstraints requestable (CA flag + pathLenConstraint).
- F5 Explicit SAN type picker in UI (DNS / IP / email / URI).

### Phase 3 — advanced
- F6 Self-signed certificate from the CSR (test certs).
- F7 RSA-PSS signatures; PKCS#12 bundle in the UI.

### Phase 5 — Post-Quantum Cryptography (PQC) ✅ DONE (deployed + prod-verified)
- BC 1.78.1 → 1.80. Added **ML-DSA** (FIPS 204: 44/65/87), **SLH-DSA** (FIPS 205: SHA2-128/192/256s),
  **Falcon** (512/1024) — keygen + CSR signing + decode + self-signed cert.
- UI: "PQC" key type + algorithm picker; PQC-aware openssl command + strength meter.
- QA on prod: ML-DSA & SLH-DSA CSRs **verify in openssl 3.6** (`verify OK`); Falcon validates via BC
  (openssl lacks the OID); ML-DSA-65 self-signed cert `Signature Algorithm: ML-DSA-65`; unknown param → 400.
  77 backend tests (10 PQC). UI generate → history confirmed live.

### Phase H — "post-quantum migration studio" (groundbreaking set)
- **H1 — Hybrid CSR (classical + PQC).** One request → a matched *pair* of CSRs (same subject/SANs):
  classical (RSA/ECDSA) for today's CAs + PQC (ML-DSA/…) for the migration. `POST /csr/hybrid`.
  (True IETF composite signatures noted as experimental follow-up.)
- **H2 — Quantum-readiness scanner.** Paste a CSR/cert or a domain → HNDL ("harvest now, decrypt
  later") risk grade, algorithm breakdown, migration recommendation. `POST /csr/quantum-scan`.
- **H3 — Review links + diff.** Shareable read-only decode links (`csr_studio_share` table) for
  team approval; side-by-side CSR diff in the UI.

## Status
- [x] Phase 1 (Ed25519 key type; decode shows keyUsage/EKU/basicConstraints; country uppercased; SAN-only CSR allowed — 63 tests)
- [x] Phase 2 (F4 basicConstraints CA:true/pathlen requestable + decoded; F5 explicit SAN type picker DNS/IP/email/URI)
- [x] Phase 3 (F6 self-signed test cert from CSR; F7 RSA-PSS signatures)
- [x] Phase 4 (G1 PKCS#12 .p12 download in UI; G2 compliance lint in Decode; G3 public-key SHA-256 fingerprint + SPKI pin) — 67 tests
