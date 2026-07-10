/* ============================================================
   api.js — backend API client for CSR operations (ES module)
   Timeouts + retries (idempotent), async job/polling, cookie+CSRF
   or bearer auth. Falls back to an in-browser DEMO engine when no
   base URL is configured.
   (ported from design api.js)
   ============================================================ */
import * as engine from "./engine.js";

const CKEY = "csrgen.api.v2";
// Backend URL is hardcoded in the app — production builds always hit the prod
// backend; local dev hits localhost. VITE_API_URL can still override for testing.
const DEFAULT_BASE = import.meta.env.VITE_API_URL
  || (import.meta.env.PROD
    ? "https://csr-studio-api-y7ca.onrender.com/api"
    : "http://localhost:8080/api");
export const DEFAULTS = {
  baseUrl: DEFAULT_BASE,
  authMode: "none",          // "cookie" | "bearer" | "none"
  token: "",
  csrfHeader: "X-CSRF-Token",
  csrfCookie: "csrftoken",
  csrfToken: "",
  timeoutMs: 30000,
  retries: 2,
  demoAsync: true,
  demoLatencyMs: 1400
};
let config = { ...DEFAULTS };
try { Object.assign(config, JSON.parse(localStorage.getItem(CKEY) || "{}")); } catch (e) {}
// The backend URL is hardcoded at build time (VITE_API_URL) and is NOT user-editable.
config.baseUrl = DEFAULT_BASE;

const clamp = (n, lo, hi, d) => { n = Number(n); return isFinite(n) ? Math.max(lo, Math.min(hi, n)) : d; };

export function getConfig() { return { ...config }; }
export function setConfig(next) {
  const c = { ...config, ...next };
  config = {
    baseUrl: DEFAULT_BASE,   // fixed — ignore any attempt to change it
    authMode: ["cookie", "bearer", "none"].includes(c.authMode) ? c.authMode : "none",
    token: (c.token || "").trim(),
    csrfHeader: (c.csrfHeader || "X-CSRF-Token").trim(),
    csrfCookie: (c.csrfCookie || "csrftoken").trim(),
    csrfToken: (c.csrfToken || "").trim(),
    timeoutMs: clamp(c.timeoutMs, 2000, 180000, 30000),
    retries: clamp(c.retries, 0, 5, 2),
    demoAsync: !!c.demoAsync,
    demoLatencyMs: clamp(c.demoLatencyMs, 200, 8000, 1400)
  };
  try { localStorage.setItem(CKEY, JSON.stringify(config)); } catch (e) {}
  return getConfig();
}
export function mode() { return config.baseUrl ? "connected" : "demo"; }
export function host() {
  if (!config.baseUrl) return "demo";
  try { return new URL(config.baseUrl, location.href).host; } catch (e) { return config.baseUrl; }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const uuid = () => (crypto.randomUUID ? crypto.randomUUID()
  : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16); }));
const backoff = (attempt) => sleep(Math.min(300 * 2 ** attempt, 4000) + Math.random() * 200);
function readCookie(name) {
  const m = document.cookie.split("; ").find(c => c.indexOf(name + "=") === 0);
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : "";
}

function headers(extra) {
  const h = { "Content-Type": "application/json", "Accept": "application/json", ...(extra || {}) };
  if (config.authMode === "bearer" && config.token) h["Authorization"] = "Bearer " + config.token;
  if (config.authMode === "cookie") {
    const tok = config.csrfToken || readCookie(config.csrfCookie);
    if (tok) h[config.csrfHeader || "X-CSRF-Token"] = tok;
  }
  return h;
}
const creds = () => (config.authMode === "cookie" ? "include" : "same-origin");

export class ApiError extends Error {
  constructor(message, fields, status) { super(message); this.name = "ApiError"; this.fields = fields || null; this.status = status; }
}

function withTimeout(url, opts) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), config.timeoutMs);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(id));
}

async function request(path, { method = "POST", body, onProgress, idemKey, retries, headers: extraHeaders } = {}) {
  const url = /^https?:/i.test(path) ? path : config.baseUrl + path;
  const max = retries != null ? retries : config.retries;
  let attempt = 0;
  while (true) {
    let res;
    try {
      const extra = { ...(idemKey ? { "Idempotency-Key": idemKey } : {}), ...(extraHeaders || {}) };
      res = await withTimeout(url, { method, headers: headers(extra), credentials: creds(), body: body != null ? JSON.stringify(body) : undefined });
    } catch (e) {
      const timeout = e.name === "AbortError";
      if (attempt < max) { attempt++; onProgress && onProgress({ phase: "retrying", attempt, reason: timeout ? "timeout" : "network" }); await backoff(attempt); continue; }
      throw new ApiError(timeout
        ? `Request to ${host()} timed out after ${Math.round(config.timeoutMs / 1000)}s.`
        : `Can't reach the backend at ${host()}. Check the URL, CORS and TLS.`, null, 0);
    }
    if ([502, 503, 504].includes(res.status) && attempt < max) {
      attempt++; onProgress && onProgress({ phase: "retrying", attempt, reason: "server" }); await backoff(attempt); continue;
    }
    let data = null; try { data = await res.json(); } catch (e) {}
    if (!res.ok) {
      const err = (data && data.error) || {};
      throw new ApiError(err.message || `Server returned ${res.status} ${res.statusText}.`, err.fields, res.status);
    }
    return { data, status: res.status };
  }
}

/* ---- request builders / response normalisers ---- */
function generateRequest(o) {
  const s = o.subject || {};
  return {
    subject: {
      commonName: s.CN || "", organization: s.O || "", organizationalUnit: s.OU || "",
      locality: s.L || "", state: s.ST || "", country: s.C || "", email: s.email || ""
    },
    subjectAltNames: (o.sans || []).map(x => ({ type: x.type, value: x.value })),
    key: o.keyType === "pqc"
      ? { algorithm: o.pqcAlgo }
      : o.keyType === "ed25519"
        ? { algorithm: "Ed25519", format: "PKCS#8" }
        : o.keyType === "ecdsa"
          ? { algorithm: "ECDSA", curve: o.size, format: "PKCS#8" }
          : { algorithm: "RSA", size: parseInt(o.size, 10), format: o.keyFormat === "pkcs1" ? "PKCS#1" : "PKCS#8", ...(o.rsaPss ? { rsaPss: true } : {}) },
    signatureHash: o.hash || "SHA-256",
    ...buildExtensions(o)
  };
}
function buildExtensions(o) {
  const hasKu = o.keyUsage && o.keyUsage.length;
  const hasEku = o.eku && o.eku.length;
  if (!hasKu && !hasEku && !o.bcCa) return {};
  const ext = { keyUsage: o.keyUsage || [], extendedKeyUsage: o.eku || [] };
  if (o.bcCa) {
    ext.basicConstraintsCa = true;
    if (o.bcPathLen !== "" && o.bcPathLen != null) ext.basicConstraintsPathLen = parseInt(o.bcPathLen, 10);
  }
  return { extensions: ext };
}
function normGenerate(r, o) {
  const d = r.details || {};
  const fallbackLabel = o.keyType === "ed25519" ? "Ed25519" : o.keyType === "ecdsa" ? "ECDSA " + o.size : "RSA " + o.size;
  return {
    csrPem: r.csr, keyPem: r.privateKey,
    keyLabel: d.keyLabel || fallbackLabel,
    keyFormat: d.keyFormat || (o.keyType === "ecdsa" ? "PKCS#8" : (o.keyFormat === "pkcs1" ? "PKCS#1" : "PKCS#8")),
    keyKind: o.keyType === "ed25519" ? "Ed25519" : o.keyType === "ecdsa" ? "ECDSA" : "RSA",
    keyDetail: d.keyDetail || "",
    sigAlg: d.signatureAlgorithm || o.hash,
    hash: o.hash, keyType: o.keyType, size: o.size,
    subject: o.subject, sans: o.sans || [], createdAt: Date.now(),
    id: r.id || null, recordPath: r.recordPath || (r.id ? "/r/" + r.id : null)
  };
}
function normDecode(r) {
  const s = r.subject || {};
  return {
    subject: { CN: s.commonName || "", O: s.organization || "", OU: s.organizationalUnit || "", L: s.locality || "", ST: s.state || "", C: s.country || "", email: s.email || "" },
    sans: (r.subjectAltNames || []).map(x => ({ type: x.type, value: x.value })),
    bits: (r.key && r.key.bits) || null,
    keyKind: (r.key && r.key.kind) || "Unknown",
    keyDetail: (r.key && r.key.detail) || "",
    verified: r.signature ? !!r.signature.valid : null,
    sigAlg: (r.signature && r.signature.algorithm) || "",
    extensions: r.extensions || null,
    keySha256: (r.key && r.key.sha256) || null,
    keyPin: (r.key && r.key.pin) || null
  };
}

/* ---- async job polling ---- */
async function pollJob(job, opts, onProgress) {
  const statusPath = job.statusUrl || ("/csr/jobs/" + job.jobId);
  const deadline = Date.now() + Math.max(config.timeoutMs * 4, 90000);
  let interval = 700;
  onProgress({ phase: "queued", status: job.status || "queued", jobId: job.jobId });
  while (true) {
    await sleep(interval);
    if (Date.now() > deadline) throw new ApiError("Timed out waiting for the CSR job to finish.", null, 0);
    let r;
    try { r = await request(statusPath, { method: "GET", retries: 1 }); }
    catch (e) { if (e.status === 0) { onProgress({ phase: "retrying", reason: "poll" }); continue; } throw e; }
    const s = r.data || {};
    const st = s.status || (s.csr ? "done" : "processing");
    if (st === "done" || s.csr) { onProgress({ phase: "done" }); return normGenerate(s.result || s, opts); }
    if (st === "error" || st === "failed") { const err = s.error || {}; throw new ApiError(err.message || "The CSR job failed on the server.", err.fields, 0); }
    onProgress({ phase: "processing", status: st, progress: s.progress, label: s.message });
    interval = Math.min(Math.round(interval * 1.25), 3000);
  }
}

/* ---- demo simulator ---- */
async function demoGenerate(opts, onProgress) {
  const L = config.demoLatencyMs;
  if (config.demoAsync) {
    onProgress({ phase: "submitting" }); await sleep(L * 0.35);
    onProgress({ phase: "queued", status: "queued", jobId: "demo_" + uuid().slice(0, 8) }); await sleep(L * 0.6);
    onProgress({ phase: "processing", status: "generating_key", label: "Generating key pair", progress: 0.35 });
    const res = await engine.generate(opts);
    onProgress({ phase: "processing", status: "signing", label: "Signing request", progress: 0.8 }); await sleep(L * 0.55);
    onProgress({ phase: "done" });
    return res;
  }
  onProgress({ phase: "submitting" }); await sleep(Math.min(L, 500));
  const res = await engine.generate(opts);
  onProgress({ phase: "done" });
  return res;
}

/* ---- public methods ---- */
export async function generate(opts, hooks) {
  const onProgress = (hooks && hooks.onProgress) || (() => {});
  if (mode() === "demo") return demoGenerate(opts, onProgress);
  onProgress({ phase: "submitting" });
  const { data, status } = await request("/csr/generate?async=true", { body: generateRequest(opts), onProgress, idemKey: uuid() });
  if (status === 202 || (data && data.jobId && !data.csr)) return pollJob(data, opts, onProgress);
  onProgress({ phase: "done" });
  return normGenerate(data, opts);
}
/** Hybrid: classical CSR (from opts) + a PQC CSR for the same identity. */
export async function hybrid(opts, pqcAlgo = "ML-DSA-65") {
  if (mode() === "demo") throw new ApiError("Hybrid CSRs require a connected backend.");
  const { data } = await request("/csr/hybrid?pqc=" + encodeURIComponent(pqcAlgo), { body: generateRequest(opts), retries: 0 });
  return {
    classical: normGenerate({ csr: data.classical.csr, privateKey: data.classical.privateKey, details: data.classical.details }, opts),
    pqc: normGenerate({ csr: data.pqc.csr, privateKey: data.pqc.privateKey, details: data.pqc.details }, { ...opts, keyType: "pqc", pqcAlgo })
  };
}
/** Quantum-readiness scan of a CSR, certificate, or live host. */
export async function quantumScan({ csr, certificate, host }) {
  if (mode() === "demo") throw new ApiError("Quantum scan requires a connected backend.");
  return (await request("/csr/quantum-scan", { body: { csr, certificate, host }, retries: config.retries })).data;
}
/** Create a read-only review share link for a CSR. Returns { id, path, createdAt }. */
export async function shareCreate(csrPem) {
  if (mode() === "demo") throw new ApiError("Review links require a connected backend.");
  return (await request("/csr/share", { body: { csr: csrPem }, retries: 0 })).data;
}
export async function shareGet(id) {
  return (await request("/csr/share/" + encodeURIComponent(id), { method: "GET", retries: config.retries })).data;
}
/** Retrieve a generated CSR snapshot by UUID (the /r/<id> permalink). CSR + metadata only. */
export async function recordGet(id) {
  return (await request("/csr/record/" + encodeURIComponent(id), { method: "GET", retries: config.retries })).data;
}

export async function selfSigned(opts, days = 365) {
  if (mode() === "demo") {
    throw new ApiError("Self-signed test certificates require a connected backend (not available in demo).");
  }
  const { data } = await request("/csr/self-signed?days=" + days, { body: generateRequest(opts), retries: 0 });
  const r = normGenerate({ csr: data.csr, privateKey: data.privateKey, details: data.details }, opts);
  r.certPem = data.certificate;
  return r;
}
export async function decode(pem) {
  if (mode() === "demo") { await sleep(Math.min(config.demoLatencyMs, 450)); return engine.decode(pem); }
  return normDecode((await request("/csr/decode", { body: { csr: pem }, retries: config.retries })).data);
}
/** Baseline compliance lint (server-side). Returns { valid, errors[], warnings[] } or null in demo. */
export async function lint(pem) {
  if (mode() === "demo") return null;
  try { return (await request("/v1/csr/validate", { body: { pem }, retries: config.retries })).data; }
  catch (e) { return null; }
}
/** Bundle a cert + key into a PKCS#12 (.p12). Returns a Blob. */
export async function pkcs12({ certificatePem, privateKeyPem, password, alias }) {
  if (mode() === "demo") throw new ApiError("PKCS#12 bundling requires a connected backend.");
  const res = await withTimeout(config.baseUrl + "/v1/convert/pkcs12", {
    method: "POST", headers: headers(), credentials: creds(),
    body: JSON.stringify({ certificatePem, privateKeyPem, password, alias: alias || "1" })
  });
  if (!res.ok) {
    let err = {};
    try { err = (await res.json()).error || {}; } catch (e) {}
    throw new ApiError(err.message || ("PKCS#12 bundling failed (" + res.status + ")"));
  }
  return await res.blob();
}
export async function match(pem, keyPem) {
  if (mode() === "demo") { await sleep(Math.min(config.demoLatencyMs, 450)); return engine.keyMatch(pem, keyPem); }
  return (await request("/csr/match", { body: { csr: pem, privateKey: keyPem }, retries: config.retries })).data;
}
/** Verify a signature (detached) or a certificate-by-issuer. Backend-only (uses Bouncy Castle for PQC). */
export async function verify(payload) {
  if (mode() === "demo") throw new ApiError("Signature verification requires a connected backend.");
  return (await request("/csr/verify", { body: payload, retries: config.retries })).data;
}
export async function testConnection() {
  if (mode() === "demo") return { ok: false, demo: true };
  try {
    const res = await withTimeout(config.baseUrl + "/health", { method: "GET", headers: headers(), credentials: creds() });
    return { ok: res.ok, status: res.status, host: host() };
  } catch (e) {
    return { ok: false, error: (e.name === "AbortError" ? "Timed out reaching " : "Network error — couldn't reach ") + host() + " (check URL / CORS / TLS).", host: host() };
  }
}

/* ---- history (server-side when connected, localStorage in demo) ---- */
const HKEY = "csrgen.history.v1";
function loadLocal() { try { return JSON.parse(localStorage.getItem(HKEY) || "[]"); } catch (e) { return []; } }
function saveLocal(list) { try { localStorage.setItem(HKEY, JSON.stringify(list)); } catch (e) {} }

// server record (flat) → the item shape the History view + reuse expect
function itemFromServer(r) {
  const ecdsa = (r.keyLabel || "").startsWith("ECDSA");
  const size = ecdsa ? (r.keyDetail || "P-256") : ((r.keyLabel || "RSA 2048").split(" ")[1] || "2048");
  return {
    id: r.id, csrPem: r.csrPem, keyPem: undefined,
    subject: { CN: r.commonName || "", O: r.organization || "", OU: "", L: "", ST: "", C: "", email: "" },
    sans: r.sans || [],
    keyLabel: r.keyLabel, keyDetail: r.keyDetail, keyFormat: r.keyFormat,
    keyKind: ecdsa ? "ECDSA" : "RSA", keyType: ecdsa ? "ecdsa" : "rsa",
    size, hash: r.signatureAlgorithm, sigAlg: r.signatureAlgorithm,
    createdAt: r.createdAt
  };
}
// generated result → server save payload (NO private key)
function payloadFromResult(res) {
  const s = res.subject || {};
  return {
    commonName: s.CN || "", organization: s.O || "",
    keyLabel: res.keyLabel, keyDetail: res.keyDetail, keyFormat: res.keyFormat,
    signatureAlgorithm: res.sigAlg || res.hash, sans: res.sans || [], csrPem: res.csrPem
  };
}

export async function historyList() {
  if (mode() === "demo") return loadLocal();
  const { data } = await request("/csr/history", { method: "GET", retries: config.retries });
  return (data || []).map(itemFromServer);
}
export async function historySave(res) {
  if (mode() === "demo") {
    const item = { ...res, id: Math.random().toString(36).slice(2) };
    saveLocal([item, ...loadLocal()].slice(0, 40));
    return item;
  }
  const { data } = await request("/csr/history", { body: payloadFromResult(res), retries: 0 });
  return itemFromServer(data);
}
export async function historyDelete(id) {
  if (mode() === "demo") { saveLocal(loadLocal().filter(h => h.id !== id)); return; }
  await request("/csr/history/" + encodeURIComponent(id), { method: "DELETE", retries: 0 });
}
export async function historyClear() {
  if (mode() === "demo") { saveLocal([]); return; }
  await request("/csr/history", { method: "DELETE", retries: 0, headers: { "X-Confirm-Clear": "yes" } });
}

/* ---- contract samples for the docs view ---- */
export const SAMPLES = {
  generate: {
    request: {
      subject: { commonName: "shop.example.com", organization: "Example Inc.", organizationalUnit: "IT", locality: "San Francisco", state: "California", country: "US", email: "admin@example.com" },
      subjectAltNames: [{ type: "DNS", value: "shop.example.com" }, { type: "DNS", value: "www.shop.example.com" }, { type: "IP", value: "203.0.113.10" }],
      key: { algorithm: "RSA", size: 2048, format: "PKCS#8" },
      signatureHash: "SHA-256"
    },
    response: {
      csr: "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----",
      privateKey: "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----",
      details: { keyLabel: "RSA 2048", keyDetail: "2048-bit", keyFormat: "PKCS#8", signatureAlgorithm: "SHA-256" }
    }
  },
  generateAsync: {
    response: { jobId: "job_8f3a21c0", statusUrl: "/csr/jobs/job_8f3a21c0", status: "queued" }
  },
  job: {
    processing: { status: "processing", progress: 0.4, message: "Generating key pair" },
    done: {
      status: "done",
      result: {
        csr: "-----BEGIN CERTIFICATE REQUEST-----\n…",
        privateKey: "-----BEGIN PRIVATE KEY-----\n…",
        details: { keyLabel: "RSA 4096", keyFormat: "PKCS#8", signatureAlgorithm: "SHA-256" }
      }
    }
  },
  decode: {
    request: { csr: "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----" },
    response: {
      subject: { commonName: "shop.example.com", organization: "Example Inc.", country: "US" },
      subjectAltNames: [{ type: "DNS", value: "shop.example.com" }],
      key: { kind: "RSA", detail: "2048-bit", bits: 2048 },
      signature: { algorithm: "sha256WithRSAEncryption", valid: true }
    }
  },
  match: {
    request: { csr: "-----BEGIN CERTIFICATE REQUEST-----\n…", privateKey: "-----BEGIN PRIVATE KEY-----\n…" },
    response: { supported: true, match: true, bits: 2048 }
  }
};

const CSRApi = { generate, hybrid, quantumScan, shareCreate, shareGet, recordGet, selfSigned, decode, lint, pkcs12, match, verify, getConfig, setConfig, mode, host, testConnection, generateRequest, historyList, historySave, historyDelete, historyClear, ApiError, SAMPLES, DEFAULTS };
export default CSRApi;
