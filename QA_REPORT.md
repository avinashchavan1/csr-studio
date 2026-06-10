# CSR Studio — QA Report (PROD)

**Tester:** QA (PKI/security focus)  ·  **Date:** 2026-06-10
**Targets:** FE https://csr-studio-7c0a4c.netlify.app · API https://csr-studio-api.onrender.com/api
**Method:** black-box against prod — `curl` + `openssl` cryptographic verification, content review of the live bundle, negative/abuse testing.

## Verdict
Core crypto is **correct and interoperable** (every generated CSR verifies in openssl; external CSRs decode; signatures valid).

**UPDATE 2026-06-10 — all 17 findings resolved (CP1–CP4 deployed + prod-verified).** 2 High + 8 Medium + 7 Low closed; test count 35 → 58. Only deliberately-deferred item: full JWT/OAuth auth (history remains shared/anonymous behind a row cap + confirm-guarded clear + rate limiting). See per-checkpoint ✅ notes below.

---

## PASSED (verified good)
- RSA 2048/3072/4096 + ECDSA P-256/P-384/P-521 → all CSRs **verify in openssl** (`self-signature verify OK`); correct key bits, curve OIDs, sig algorithms.
- Hashes SHA-256/384/512 produce matching `*WithRSA/ECDSA` sig algorithms.
- PKCS#8 (`BEGIN PRIVATE KEY`) vs PKCS#1 (`BEGIN RSA PRIVATE KEY`) correct.
- Weak keys rejected: RSA <2048, 2047, 8192 (policy 2048/3072/4096). Weak hashes rejected: SHA-1, MD5.
- Decode interop: external openssl-generated CSR parsed correctly, `signature.valid=true`. EC signatures **re-verified server-side** (better than the demo engine).
- Match: correct pair → `match:true`; mismatch → `false`; EC → `supported:false`.
- Async: `?async=true` → 202 + job poll → `done`; unknown job → 404; **Idempotency-Key** returns the same CSR.
- History: **private key is NOT stored** even if posted (field ignored) ✓.
- CORS: allowed origin echoed; disallowed origin gets no ACAO. HTTP→HTTPS 301. DB persistence to Supabase confirmed.

---

## ISSUES

| ID | Sev | Area | Finding | Evidence |
|----|-----|------|---------|----------|
| **H-1** | High | Decode correctness | **IP-address SANs decode to hex**, not dotted-quad. `10.0.0.9` → `#0a000009`. `CsrParser` uses `GeneralName.getName().toString()` on an `ASN1OctetString`. | `decode` D1 returned `{'type':'IP','value':'#0a000009'}` |
| **H-2** | High | Security / content | UI says key match is **"compared locally, never sent anywhere"** — **false in connected mode**: `/csr/match` POSTs the **private key** to the server. Misleading for a security tool. | live bundle still contains the string; `/csr/match` body carries `privateKey` |
| **M-1** | Med | Auth / abuse | **No auth on any endpoint.** History is **global + shared**: any visitor can `DELETE /csr/history` (wipe everyone's data → 204) or flood the 500 MB Supabase DB, and **sees everyone's CSRs** (domain/org disclosure). | G5 public clear → 204 |
| **M-2** | Med | Error handling | **Invalid IP SAN → HTTP 500** (should be 400) and leaks `Internal error: IP Address is invalid`. | H3 |
| **M-3** | Med | Error handling | **Malformed JSON / unhandled errors → 500** leaking parser/exception internals (`Internal error: JSON parse error: Unexpected character…`). Generic handler returns `ex.getMessage()`. | C malformed JSON |
| **M-4** | Med | Correctness | **Unknown key algorithm silently coerced to RSA.** `algorithm:"DSA"` → 200, `keyLabel:"RSA 2048"`. Anything not ECDSA becomes RSA — no error. | C "DSA" → 200 RSA |
| **M-5** | Med | Validation (API) | Subject fields unvalidated on the contract path: `country:"USA"` (3-letter) → 200; bad email → 200; DNS SAN `"has spaces .com"` → 200; **CN not auto-added to SAN** and CN-only requests produce a **SAN-less CSR** (browser-unusable). UI mitigates, direct API does not. | C country/email/DNS, B1 |
| **M-6** | Med | DoS | **No rate limiting / size caps.** RSA-4096 = ~9.7 s CPU each; 5000-SAN request accepted (4.9 s). Unauthenticated → cheap amplification on a free dyno. | H4, H6 |
| **M-7** | Med | Security headers | Missing `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, CSP on API responses. | A2 |
| **M-8** | Med | Secret caching | Private-key-bearing `/csr/generate` response sets **no `Cache-Control: no-store`**. POSTs aren't CDN-cached, but back/forward cache & intermediaries can retain. | H1 |
| **L-1** | Low | Validation | `POST /csr/history` accepts arbitrary `csrPem` ("NOT A CSR") → 200 (no CSR validation). | G3 |
| **L-2** | Low | Validation | No server-side SAN **dedup** or **count cap**. | H6 |
| **L-3** | Low | Consistency | ECDSA **P-521** accepted by API though UI offers only P-256/P-384; strength meter has no P-521 case. | C P-521 → 200 |
| **L-4** | Low | PKI | **Wildcard SANs not validated** (leftmost-label-only rule). `*.*.com` / `a.*.com` would pass. | review |
| **L-5** | Low | PKI best-practice | **Email placed in subject DN** (`emailAddress`) — deprecated for TLS by CA/B Forum; belongs in SAN `rfc822Name` if anywhere. | review |
| **L-6** | Low | PKI feature gap | CSR carries **only SAN** — no option for **keyUsage / extendedKeyUsage / basicConstraints**. Fine for public CAs (they set these), limiting for internal CAs that honor CSR extensions. | review |
| **L-7** | Low | Content | Decode `signature.algorithm` shown as `SHA256WITHRSA` (uppercase) vs conventional `sha256WithRSAEncryption`. | D1 |
| **L-8** | Low | UX | Generic bean-validation messages (`must not be null`) surfaced to users. | C missing key |

---

## PKI knowledge-gap notes (expert review)
- **CN-in-SAN is mandatory** (RFC 6125 / CA-B Forum; browsers ignore CN). The backend should **auto-append the CN to SAN** (dedup), guaranteeing usable certs for *all* API consumers, not just the UI. (→ M-5)
- **IP SAN encoding** is correct on the *generate* side (openssl shows `IP Address:203.0.113.10`); only *decode* mis-renders it (→ H-1).
- **Server-side key generation + returning the private key over the API** is an inherent posture choice. Highest-assurance flows generate the key client-side (or in an HSM) so it never transits. At minimum, the match feature should be **client-only** so keys never leave the browser (fixes H-2 cleanly).
- Email-in-DN, missing EKU/keyUsage, wildcard validation = maturity gaps, not correctness bugs.

---

## Remediation plan (checkpoints)

### QA-CP1 — High severity ✅ DONE (deployed + prod-verified 2026-06-10)
1. **H-1 ✅** `CsrParser` now decodes IP SANs via `InetAddress.getByAddress` → dotted-quad/IPv6. Regression test added. Verified on prod (`10.0.0.9`, `192.168.1.250`).
2. **H-2 ✅** `DecodeView` runs `engine.keyMatch` in-browser; `/csr/match` no longer receives the private key. The "compared locally, never sent anywhere" copy is now accurate. FE redeployed.

> Deploy note: capped HikariCP pool to 5 (Supabase free = 15 conns); a deploy under load can still exhaust the pool during instance overlap → if a deploy shows `update_failed` with `Unable to determine Dialect`, suspend+resume the service (frees connections) then redeploy.

### QA-CP2 — Validation & error handling ✅ DONE (deployed + prod-verified 2026-06-10)
3. **M-2/M-3 ✅** `HttpMessageNotReadableException` → 400 ("Malformed or unreadable request body."); invalid IP/SAN → 400 (`CryptoException`); generic 500 now returns a static message and logs the cause server-side (no leakage).
4. **M-4 ✅** Unknown key algorithm → 400 ("Unsupported key algorithm…"), no silent RSA fallback.
5. **M-5 ✅** Country (`^[A-Za-z]{2}$`) + email (`@Email`) bean-validated → 400 with `error.fields`; DNS/IP SAN syntax validated; **CN auto-added to SAN (deduped)** so every CSR has a usable SAN. All verified on prod.

### QA-CP3 — Hardening ✅ DONE (deployed + prod-verified 2026-06-10; JWT auth deferred by owner)
6. **M-1 (lite) ✅** History capped at 500 rows (oldest trimmed); bulk `DELETE` requires `X-Confirm-Clear: yes`. Full per-user auth (JWT) remains deferred — history is still shared/anonymous.
7. **M-6 ✅** Per-IP fixed-window rate limit (120/min) on `/csr/generate|match|history` POST → 429. Verified: 160 concurrent → 120 OK + 40×429.
8. **M-7 ✅** Security headers filter: HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
9. **M-8 ✅** `Cache-Control: no-store` on all API responses (verified on key-bearing `/csr/generate`).

> Residual: under extreme concurrent load the DB pool (5, Supabase free) can exhaust → 500s; the rate limit keeps normal traffic well clear. Revisit pool/queueing if real load grows.

### QA-CP4 — PKI completeness & polish ✅ DONE (deployed + prod-verified 2026-06-10)
10. **L-1/L-2 ✅** History rejects non-CSR `csrPem`; SANs deduped + capped at 100 (101 → 400).
11. **L-3 ✅** P-521 added to UI + strength meter (backend already supported); verifies in openssl.
12. **L-4/L-5 ✅** Wildcard enforced leftmost-label-only (`a.*.com` → 400, `*.example.com` → 200); subject email now also emitted as SAN `rfc822Name`.
13. **L-6 ✅** keyUsage + extendedKeyUsage requestable (UI chips); openssl confirms `X509v3 Key Usage (critical)` + `Extended Key Usage` in the CSR.
14. **L-7/L-8 ✅** Decode shows `SHA256withRSA`; friendlier validation messages.

---

## Test coverage gaps to add (regression)
- Unit: IP-SAN decode round-trip (gen→decode IP equals input); unknown-algorithm rejection; country/email/DNS validation; CN-auto-in-SAN.
- Web: 400 (not 500) for malformed JSON and bad IP; security headers present; `no-store` on generate.
- Abuse: history requires auth / rate limit (once added).
