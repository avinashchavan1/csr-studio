# CSR Studio — Deployment ($0/mo, no credit card)

Production-tested free stack. Frontend on Netlify, backend on Render (Docker),
Postgres on Supabase, triple-redundant keep-alive.

## Stack
- **Frontend:** Netlify (auto-deploy on push) — `netlify.toml` at repo root.
- **Backend:** Render free web service (Docker) — `render.yaml` + `backend/Dockerfile`.
- **DB:** Supabase Postgres (free 500 MB) — **Supavisor POOLER** endpoint, port **5432** (session mode).
- **Push:** Web Push (VAPID) — `npx web-push generate-vapid-keys`.
- **Auth:** self-hosted JWT + Google OAuth (frontend implicit flow).
- **Keep-alive (Render free spins down at 15 min idle):**
  1. cron-job.org — every 5 min, primary, email alert on failure.
  2. UptimeRobot — every 5 min, secondary (create from dashboard; free plan blocks `newMonitor` API).
  3. GitHub Actions — every 20 min, last-resort backup (`.github/workflows/keep-alive.yml`).

## This repo's specifics
- Backend serves everything under **`/api`** (Spring `server.servlet.context-path=/api`).
  So health = **`/api/health`**, generate = `/api/csr/generate`, etc. Matches the keep-alive probes.
- Render listens on `$PORT` (wired via `server.port=${PORT:8080}`).
- CORS origin comes from env **`APP_CORS_ALLOWED_ORIGINS`** — set it to the Netlify URL.
- Frontend API base from **`VITE_API_URL`** (e.g. `https://csr-studio-api.onrender.com/api`).
  Local default: `http://localhost:8080/api`.
- Health endpoint has no auth (no Spring Security yet) so any method (incl. HEAD) is allowed.

## Setup order (~1 hour)
1. Push to a **public** GitHub repo (Dockerfile already at `backend/Dockerfile`).
2. **Supabase:** create project → copy the **POOLER** string (Project Settings → Database):
   `postgresql://postgres.<ref>:<pw>@aws-1-<region>.pooler.supabase.com:5432/postgres`.
   The DIRECT endpoint (`db.<ref>.supabase.co`) is **IPv6-only** → fails from Render free.
3. **Render:** New → Blueprint → connect repo (`render.yaml`). Set env vars (see below).
4. **Netlify:** connect repo. Set `VITE_API_URL=https://<app>-api.onrender.com/api`. Deploy.
   Then set Render's `APP_CORS_ALLOWED_ORIGINS` to the Netlify origin and redeploy.
5. **Triple keep-alive** (see commands below).

### Render env vars
| Key | Now? | Value |
|-----|------|-------|
| `APP_CORS_ALLOWED_ORIGINS` | **yes** | `https://<app>.netlify.app` |
| `DATABASE_URL` | when DB added | `jdbc:postgresql://aws-1-<region>.pooler.supabase.com:5432/postgres?sslmode=require` |
| `DB_USERNAME` | when DB added | `postgres.<project-ref>` (pooler routes by username prefix — NOT bare `postgres`) |
| `DB_PASSWORD` | when DB added | — |
| `JWT_SECRET` | when auth added | `openssl rand -base64 48` |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | when push added | `npx web-push generate-vapid-keys` |

### Keep-alive commands
**a) cron-job.org** (Settings → API for key):
```bash
curl -X PUT https://api.cron-job.org/jobs \
  -H "Authorization: Bearer <KEY>" -H "Content-Type: application/json" \
  -d '{"job":{"url":"https://<app>-api.onrender.com/api/health","enabled":true,
        "requestMethod":0,"requestTimeout":30,
        "schedule":{"timezone":"UTC","hours":[-1],"mdays":[-1],
          "minutes":[0,5,10,15,20,25,30,35,40,45,50,55],"months":[-1],"wdays":[-1]},
        "notification":{"onFailure":true,"onFailureCount":3,"onDisable":true}}}'
```
**b) UptimeRobot** — dashboard: HTTP(s), URL `/api/health`, 5 min, email alert.
**c) GitHub Actions** — `.github/workflows/keep-alive.yml` (already in repo; update the URL).

## Gotchas (read before reusing)
- **Never rename a Hibernate `@Table`/`@Column` on a live DB.** `ddl-auto=update` does NOT rename —
  it creates an empty new table and **orphans your data**. Run explicit `ALTER TABLE … RENAME` first.
  (Also: all tables in this project are prefixed `csr_studio_` — see `CLAUDE.md`.)
- Supabase direct endpoint is IPv6-only; Render free has no IPv6 egress → `SocketException: Network unreachable`. Use the POOLER.
- Pooler ports: **5432 = session mode** (DDL works — needed for `ddl-auto`); 6543 = transaction mode (breaks auto-migration). Use 5432.
- Pooler username MUST be `postgres.<project-ref>`, not `postgres`.
- API client must throw on non-OK **before** any null-return early-exit, or a 403 with empty body
  returns `null` → `data.filter(...)` crashes. (Our `api.js` already throws `ApiError` on non-OK.)
- GH Actions free crons drift 80–260 min — backup only.
- cron-job.org auto-deletes a job after ~5 consecutive failures (e.g. cold-start cascade). Enable `onFailure` + `onDisable` email.
- iOS PWA: avoid `viewport-fit=cover` + fixed-height shell; use body scroll + `position:fixed;bottom:0` nav + padding.
- `index.html` / `sw.js` / `manifest.json` must be no-cache (done in `netlify.toml`).
- No staging — every push is production. Back up before schema changes.
- Token in localStorage = XSS risk; JWT 30-day expiry is the tradeoff. Use httpOnly cookies for higher security.

## App status vs this strategy
- **DB / Supabase — IMPLEMENTED.** Spring Data JPA persists CSR history in table
  `csr_studio_csr_history` (CSR + metadata only — never private keys). Set `DATABASE_URL`
  (Supavisor POOLER, port 5432), `DB_USERNAME` (`postgres.<ref>`), `DB_PASSWORD` in Render.
  Without them the app falls back to in-memory H2 and still runs. `ddl-auto=update` creates
  the table on first boot. Async generation jobs remain in-memory (ephemeral by design).
- **JWT + Google OAuth — NOT built** (deferred). `JWT_SECRET` unused for now.
- **Web Push (VAPID) — NOT built** (deferred). `VAPID_*` unused for now.

## Cost
$0/mo, no card. Netlify 100 GB bw · Render 750h · Supabase 500 MB + 5 GB egress ·
cron-job.org unlimited 1-min · UptimeRobot 50 monitors @ 5 min · GH Actions free on public repos.
