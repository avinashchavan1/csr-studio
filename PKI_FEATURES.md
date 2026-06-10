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

## Status
- [x] Phase 1 (Ed25519 key type; decode shows keyUsage/EKU/basicConstraints; country uppercased; SAN-only CSR allowed — 63 tests)
- [ ] Phase 2  [ ] Phase 3
