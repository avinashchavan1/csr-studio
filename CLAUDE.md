# CSR Studio — project conventions

## Database tables

**Every DB table MUST be prefixed with the app name `csr_studio_` (underscore separated).**

Examples:
- users        → `csr_studio_user`
- csr_history  → `csr_studio_csr_history`
- jobs         → `csr_studio_job`
- audit_log    → `csr_studio_audit_log`

Rules:
- Use **underscore** separators (not hyphens) — standard SQL, no quoting needed.
- Singular table names after the prefix (`csr_studio_user`, not `..._users`) unless an
  existing table dictates otherwise.
- In JPA/Hibernate entities, set it explicitly: `@Table(name = "csr_studio_user")`.
- In Flyway/Liquibase migrations and raw SQL, use the same prefixed name.

> Status: persistence is live. Existing table: `csr_studio_csr_history` (CSR + metadata,
> never private keys). H2 in-memory for local/test; Postgres (Supabase) in prod via
> `DATABASE_URL`. Async generation jobs are intentionally in-memory (not persisted).

## Project layout
- `backend/`  — Spring Boot 3 + Java 21 + Bouncy Castle (crypto + REST contract)
- `frontend/` — Vite + React (CSR Studio UI)
- See `README.md`, `IMPLEMENTATION_PLAN.md`, `BACKEND_PLAN.md`.
