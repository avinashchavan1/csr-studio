# CSR Studio

A backend-driven Certificate Signing Request generator. React frontend (from the
Claude Design handoff) + Java/Spring Boot backend doing the real cryptography with
Bouncy Castle.

```
csr-generator/
├── backend/                Spring Boot 3 + Java 21 + Bouncy Castle (the crypto)
├── frontend/               Vite + React (the CSR Studio UI)
├── BACKEND_PLAN.md         backend design + CA library research
├── IMPLEMENTATION_PLAN.md  checkpoint plan + status (all done)
└── README.md               this file
```

## Run both

Terminal 1 — backend (port 8080):
```bash
cd backend && mvn spring-boot:run
```

Terminal 2 — frontend (port 5173):
```bash
cd frontend && npm install && npm run dev
```

Open http://localhost:5173. The app defaults to **connected** mode against
`http://localhost:8080`. Switch to in-browser **demo** mode (no backend) in the
Server / API tab.

## Features

- **Generate** — RSA (2048/3072/4096) or ECDSA (P-256/P-384); SHA-256/384/512;
  PKCS#8 or PKCS#1 (RSA) private key; subject + multi-domain SANs (auto DNS/IP);
  quick-start presets; key-strength meter; live `openssl` command; copy/download.
- **Decode / Inspect** — paste a CSR → subject, SANs, key, signature validity;
  optional private-key ↔ CSR match check.
- **History** — every generation saved in the browser; reuse / re-download / clear.
- **Server / API** — backend URL, auth (cookie+CSRF / bearer / none), timeouts +
  retries, demo behaviour, and the full API contract with copy-ready curl.
- **Async jobs** — connected generate uses `?async=true` → 202 + job polling with a
  live progress stepper. Idempotency-Key dedupes retries.
- **History persistence** — connected mode stores history server-side (Postgres via JPA,
  table `csr_studio_csr_history`, CSR + metadata only — **never** private keys); demo mode
  uses browser localStorage.
- **Themes** — Slate / SaaS / Terminal + accent / density / grid (Tweaks panel).

## API contract (backend)

```
GET  /health
POST /csr/generate[?async=true]   200 {csr,privateKey,details} | 202 {jobId,statusUrl,status}
GET  /csr/jobs/{jobId}            {status,progress,message,result,error}
POST /csr/decode                  {subject,subjectAltNames,key,signature}
POST /csr/match                   {supported,match,bits}
GET    /csr/history               [ {id,commonName,...,csrPem,createdAt} ]   (no private keys)
POST   /csr/history               save a record
DELETE /csr/history/{id}          delete one
DELETE /csr/history               clear all
Errors: non-2xx → { error: { message, fields } }
```
All paths are under the `/api` context-path (e.g. `/api/csr/generate`).

The backend also exposes the earlier `/api/v1/*` endpoints (parse/validate/convert/pkcs12);
see `backend/README.md`.

## Tests

Backend: `cd backend && mvn test` — 35 tests (key gen, CSR build, parse, validate,
match, PEM/DER/PKCS#12 convert, contract mapping, MockMvc endpoints, async job
lifecycle, idempotency, error shape).

## Security notes

- Private keys are generated server-side and returned over the API for this build.
  For production, keep keys in a KMS/HSM and never return them — see `BACKEND_PLAN.md`.
- CORS allows `http://localhost:5173` / `:3000` with credentials (configurable via
  `app.cors.allowed-origins`).
