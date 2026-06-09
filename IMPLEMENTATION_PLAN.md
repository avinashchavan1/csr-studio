# CSR Studio — Implementation Plan (design handoff → real app)

Design source: Claude Design bundle "CSR Studio". Frontend is **backend-driven**;
the browser only collects input and renders what the server returns. The design's
`api.js` defines the exact contract the backend must satisfy.

## API contract (from design `api.js`) — base URL configurable

```
POST {base}/csr/generate
  200 { csr, privateKey, details:{ keyLabel, keyDetail, keyFormat, signatureAlgorithm } }
  202 { jobId, statusUrl, status:"queued" }                       (async path)
GET  {base}/csr/jobs/{jobId}
  200 { status:"queued|processing|done|error", progress?, message?,
        result?:{ csr, privateKey, details }, error? }
POST {base}/csr/decode  → 200 { subject, subjectAltNames, key:{kind,detail,bits}, signature:{algorithm,valid} }
POST {base}/csr/match   → 200 { supported, match, bits }
GET  {base}/health      → 200
Errors: non-2xx → { error:{ message, fields? } }   fields keyed by commonName|email|country
Auth: cookie+CSRF | bearer | none.  Generate carries Idempotency-Key header.
```

### Generate request shape
```json
{
  "subject": { "commonName","organization","organizationalUnit","locality","state","country","email" },
  "subjectAltNames": [{ "type":"DNS|IP", "value":"..." }],
  "key": { "algorithm":"RSA", "size":2048, "format":"PKCS#8|PKCS#1" }
       | { "algorithm":"ECDSA", "curve":"P-256|P-384", "format":"PKCS#8" },
  "signatureHash": "SHA-256|SHA-384|SHA-512"
}
```

## Gaps vs current backend (milestones 1–4)
- Endpoints live at `/api/v1/*` with different shapes → need contract-shaped layer at `/csr/*`, `/health`.
- ECDSA (design calls EC "ECDSA", curves P-256/P-384). Have EC; align naming + sig (SHA-384/512).
- PKCS#1 vs PKCS#8 private key output (RSA). Currently PKCS#8 only.
- `signatureHash` "SHA-256" style → map to JCA sig name per key type.
- Decode response shape differs (key.kind/detail/bits, signature.algorithm/valid).
- `/csr/match` — verify private key matches CSR public key. New.
- Async job flow (202 + polling) + in-memory job store + idempotency dedupe. New.
- Error body `{ error:{ message, fields } }` with field mapping. New (currently ApiError flat).
- CORS for the React dev server. New.

## Checkpoints

- **CP-A — BE contract endpoints (sync).** `/health`, `POST /csr/generate` (RSA+ECDSA, PKCS#1/#8),
  `POST /csr/decode`, `POST /csr/match`. Contract DTOs, error shape, CORS. BE tests. ✅ when `mvn test` green.
- **CP-B — BE async + idempotency.** 202 + `GET /csr/jobs/{id}`, in-memory job store, Idempotency-Key
  dedupe, progress phases. BE tests for job lifecycle + idempotency.
- **CP-C — React scaffold.** Vite + React. App shell, sidebar nav, topbar, theming (Slate/SaaS/Terminal +
  accent/density/grid), shared components (Icon/Field/Button/CodeBlock/Pill/Segmented/Switch/toasts),
  CSS port, API client (timeouts/retries/auth/async-poll/demo).
- **CP-D — React Generate + Decode views.** Full forms, presets, SAN chips, strength meter, live openssl,
  progress stepper, result cards; decode + key-match.
- **CP-E — React History + Server views + app wiring.** localStorage history, reuse; backend connection,
  auth, reliability, demo behaviour, contract docs.
- **CP-F — Integration + verify.** Run BE + FE together, connected-mode e2e, fix issues.

## Test strategy (BE-heavy, per user)
- Unit: KeyPairService (RSA/EC/Ed25519/ECDSA curves), CsrService (subject/SAN/sig), CsrParser
  (decode fields/SAN/key/sig-valid), ValidationService (policy), ConversionService (PEM/DER/PKCS12),
  MatchService (match/mismatch/unsupported), JobService (lifecycle/idempotency), hash→sigAlg mapping,
  PKCS#1 vs PKCS#8 output.
- Web layer (MockMvc): each endpoint happy-path + validation error (400 + error.fields shape) +
  decode invalid PEM + match mismatch + async 202 + job poll + health.
- Round-trip: generate → decode → match (assert valid + matches).
- openssl cross-check where feasible in a test (optional).

## Status
- [x] CP-A (30 tests: keygen, CSR, parse, validate, match, convert, contract gen/decode/match, MockMvc, health, error shape)
- [x] CP-B (35 tests total: async 202+job poll, idempotency sync+async, unknown job 404)
- [x] CP-C (Vite+React scaffold, CSS port, ui components, data/engine/api ES modules, TweaksPanel, deps installed)
- [x] CP-D (GenerateView: presets, SAN chips, strength, openssl, async progress stepper, result+next-steps; DecodeView: decode+key-match)
- [x] CP-E (HistoryView, ServerView w/ auth+reliability+demo+contract docs, useTweaks, App shell; `npm run build` green — 150 modules)
- [x] CP-F (BE+FE running together; CORS preflight OK; async generate+poll e2e; React generate→backend→CSR+key rendered, 0 console errors)
- [x] CP-G (Postgres persistence: JPA + `csr_studio_csr_history` entity + history CRUD API; H2 local/test, Postgres via DATABASE_URL; 40 tests total inc. no-private-key-persisted safety test)
- [x] CP-H (frontend History wired to server in connected mode / localStorage in demo; verified in preview — server record renders, no private key; mode-aware copy)

## Deferred (user said ignore for now)
- JWT + Google OAuth (Spring Security)  ·  Web Push (VAPID)
