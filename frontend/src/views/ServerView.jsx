/* Backend connection, auth, reliability, demo behaviour + API contract
   (ported from design views-server.jsx) */
import React, { useState } from "react";
import { Icon, Field, TextInput, Segmented, Button, CodeBlock, Pill, Switch } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import { copyText } from "../lib/data.js";

function jsonStr(o) { return JSON.stringify(o, null, 2); }

// SHA-256 (hex) of the edit password. Rotate by replacing this hash.
const PW_HASH = "54fbe923486a4d16021542f4bb5f4bd76d58f33e0a99e0d551160a35ed43eeb7";
const UNLOCK_KEY = "csrgen.server.unlocked";
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function SetRow({ title, desc, children }) {
  return (
    <div className="set-row">
      <div className="set-main">
        <div className="set-title">{title}</div>
        {desc && <div className="set-desc">{desc}</div>}
      </div>
      <div className="set-ctrl">{children}</div>
    </div>
  );
}

export function ServerView({ push, onConfigChange }) {
  const [c, setC] = useState(api.getConfig());
  const [status, setStatus] = useState(null);
  const [testing, setTesting] = useState(false);
  const set = (k, v) => setC(p => ({ ...p, [k]: v }));
  const mode = api.mode();

  const [unlocked, setUnlocked] = useState(() => {
    try { return sessionStorage.getItem(UNLOCK_KEY) === "1"; } catch (e) { return false; }
  });
  const [pw, setPw] = useState("");
  const [unlocking, setUnlocking] = useState(false);

  async function unlock() {
    setUnlocking(true);
    try {
      if ((await sha256Hex(pw)) === PW_HASH) {
        setUnlocked(true); setPw("");
        try { sessionStorage.setItem(UNLOCK_KEY, "1"); } catch (e) {}
        push("Editing unlocked");
      } else {
        push("Incorrect password", "err");
      }
    } finally { setUnlocking(false); }
  }
  function lock() {
    setUnlocked(false);
    try { sessionStorage.removeItem(UNLOCK_KEY); } catch (e) {}
    push("Editing locked");
  }

  function save() {
    if (!unlocked) { push("Unlock editing first", "err"); return; }
    const next = api.setConfig(c);
    setC(next); setStatus(null);
    onConfigChange && onConfigChange();
    push(next.baseUrl ? "Saved — connected to " + api.host() : "Saved — running in demo mode");
  }
  async function test() {
    if (!unlocked) { push("Unlock editing first", "err"); return; }
    setTesting(true); setStatus(null);
    api.setConfig(c); onConfigChange && onConfigChange();
    setStatus(await api.testConnection()); setTesting(false);
  }

  const authHeaderPreview = c.authMode === "bearer"
    ? { "Authorization": "Bearer " + (c.token || "‹token›") }
    : c.authMode === "cookie"
      ? { [c.csrfHeader || "X-CSRF-Token"]: "‹value of " + (c.csrfCookie || "csrftoken") + " cookie›", "Cookie": "session=…  (sent via credentials: 'include')" }
      : {};

  const ENDPOINTS = [
    { method: "POST", path: "/csr/generate", desc: "Create a key pair and a signed PKCS#10 request.", key: "generate" },
    { method: "POST", path: "/csr/decode", desc: "Parse a PEM request; return subject, SANs, key info and signature validity.", key: "decode" },
    { method: "POST", path: "/csr/match", desc: "Confirm a private key corresponds to the public key inside a CSR.", key: "match" }
  ];
  const base = c.baseUrl || "https://your-backend.example.com/api";
  const curl = (ep) =>
    `curl -X ${ep.method} ${base + ep.path} \\\n` +
    `  -H "Content-Type: application/json" \\\n` +
    (c.authMode === "bearer" ? `  -H "Authorization: Bearer ${c.token || "$TOKEN"}" \\\n`
      : c.authMode === "cookie" ? `  -H "${c.csrfHeader || "X-CSRF-Token"}: $CSRF" --cookie "session=$SESSION" \\\n` : "") +
    (ep.key === "generate" ? `  -H "Idempotency-Key: $(uuidgen)" \\\n` : "") +
    `  -d '${JSON.stringify(api.SAMPLES[ep.key].request)}'`;

  return (
    <div className="stack fade-in" style={{ maxWidth: 880, margin: "0 auto" }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="server" /></span>
          <div><h3>Backend connection</h3><div className="desc">Where the app sends CSR requests. Leave blank to run the in-browser demo.</div></div>
          <span style={{ marginLeft: "auto" }}>
            {mode === "connected" ? <Pill kind="ok" icon="check">Connected · {api.host()}</Pill> : <Pill kind="warn" icon="info">Demo mode</Pill>}
          </span>
        </div>
        <div className="card-body fgroup">
          <Field label="API base URL" hint="Hardcoded into the app at build time — not editable. Every endpoint is relative to this (e.g. {base}/csr/generate).">
            <div className="input mono" style={{ background: "var(--surface-3)", color: "var(--text-muted)", userSelect: "all", cursor: "default" }}>
              {c.baseUrl}
            </div>
          </Field>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <span className="ico" style={{ color: unlocked ? "var(--success)" : "var(--warning)" }}>
            <Icon name={unlocked ? "check" : "lock"} />
          </span>
          <div>
            <h3>{unlocked ? "Editing unlocked" : "Settings locked"}</h3>
            <div className="desc">{unlocked
              ? "Connection, auth and reliability settings can be edited and saved."
              : "Enter the password to edit the settings below."}</div>
          </div>
          {unlocked && <span style={{ marginLeft: "auto" }}><Button variant="ghost" size="sm" icon="lock" onClick={lock}>Lock</Button></span>}
        </div>
        {!unlocked && (
          <div className="card-body">
            <div className="input-row">
              <input className="input" type="password" value={pw} placeholder="Edit password"
                onChange={e => setPw(e.target.value)} onKeyDown={e => { if (e.key === "Enter") unlock(); }} />
              <Button variant="primary" icon="lock" loading={unlocking} onClick={unlock}>Unlock</Button>
            </div>
          </div>
        )}
      </div>

      <fieldset disabled={!unlocked}
        style={{ border: 0, margin: 0, padding: 0, minInlineSize: 0, display: "flex", flexDirection: "column", gap: 22, opacity: unlocked ? 1 : 0.6 }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="lock" /></span>
          <div><h3>Authentication</h3><div className="desc">How requests prove who they are.</div></div>
        </div>
        <div className="card-body fgroup">
          <Field label="Method">
            <Segmented value={c.authMode} onChange={v => set("authMode", v)}
              options={[{ value: "cookie", label: "Session cookie + CSRF" }, { value: "bearer", label: "Bearer token" }, { value: "none", label: "None" }]} />
          </Field>

          {c.authMode === "cookie" && (
            <>
              <div className="warn-strip" style={{ background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
                <Icon name="info" style={{ color: "var(--accent)" }} />
                <span>Requests are sent with <code>credentials: "include"</code>, so your <b>session cookie</b> rides along. The client reads the CSRF token from a cookie and echoes it in a header. Your server must set <code>Access-Control-Allow-Credentials: true</code> and a specific <code>Access-Control-Allow-Origin</code> (not <code>*</code>).</span>
              </div>
              <div className="frow">
                <Field label="CSRF header name" hint="Header the token is sent in.">
                  <TextInput mono value={c.csrfHeader} onChange={v => set("csrfHeader", v)} placeholder="X-CSRF-Token" />
                </Field>
                <Field label="CSRF cookie name" hint="Cookie the token is read from.">
                  <TextInput mono value={c.csrfCookie} onChange={v => set("csrfCookie", v)} placeholder="csrftoken" />
                </Field>
              </div>
              <Field label="CSRF token override" optional hint="Leave blank to read the token from the cookie above. Set only if your token isn't cookie-readable.">
                <TextInput mono value={c.csrfToken} onChange={v => set("csrfToken", v)} placeholder="(auto — from cookie)" />
              </Field>
            </>
          )}
          {c.authMode === "bearer" && (
            <Field label="Bearer token" hint="Sent as “Authorization: Bearer …”. Stored only in this browser.">
              <TextInput mono type="password" value={c.token} onChange={v => set("token", v)} placeholder="eyJhbGciOi…" />
            </Field>
          )}
          {c.authMode === "none" && <div className="muted" style={{ fontSize: 13 }}>No auth headers are added. Fine for a trusted internal network only.</div>}

          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6 }}>Headers added to every request</div>
            <CodeBlock title="request headers" dots={false} value={jsonStr({ "Content-Type": "application/json", ...authHeaderPreview })} />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="refresh" /></span>
          <div><h3>Reliability</h3><div className="desc">Timeouts and automatic retries.</div></div>
        </div>
        <div className="card-body">
          <SetRow title="Request timeout" desc="Abort and surface an error if the server is silent this long.">
            <input className="range" type="range" min="5" max="120" step="5"
              value={Math.round(c.timeoutMs / 1000)} onChange={e => set("timeoutMs", e.target.value * 1000)} />
            <span className="set-val">{Math.round(c.timeoutMs / 1000)}s</span>
          </SetRow>
          <SetRow title="Automatic retries" desc="Retry network errors, timeouts and 502/503/504 with exponential back-off.">
            <input className="range" type="range" min="0" max="5" step="1"
              value={c.retries} onChange={e => set("retries", +e.target.value)} />
            <span className="set-val">{c.retries === 0 ? "off" : c.retries + "×"}</span>
          </SetRow>
          <div className="warn-strip" style={{ marginTop: 14, background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
            <Icon name="info" style={{ color: "var(--accent)" }} />
            <span>Generate requests carry a per-attempt <code>Idempotency-Key</code> so a retry never creates a second key pair — dedupe on it server-side.</span>
          </div>
        </div>
      </div>

      {mode === "demo" && (
        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="terminal" /></span>
            <div><h3>Demo behaviour</h3><div className="desc">Preview the production UX without a backend.</div></div>
          </div>
          <div className="card-body">
            <SetRow title="Simulate async job" desc="Submit → queue → poll for the result, with a live progress stepper — exactly like a slow backend.">
              <Switch value={c.demoAsync} onChange={v => set("demoAsync", v)} label="Simulate async job" />
            </SetRow>
            <SetRow title="Simulated latency" desc="How long the fake job stages take.">
              <input className="range" type="range" min="400" max="4000" step="200"
                value={c.demoLatencyMs} onChange={e => set("demoLatencyMs", +e.target.value)} />
              <span className="set-val">{(c.demoLatencyMs / 1000).toFixed(1)}s</span>
            </SetRow>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-body">
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <Button variant="primary" icon="check" onClick={save}>Save settings</Button>
            <Button variant="ghost" icon="refresh" loading={testing} onClick={test}>Test connection</Button>
          </div>
          {status && (
            <div className="warn-strip" style={{
              marginTop: 14,
              background: status.ok ? "var(--success-soft)" : "var(--danger-soft)",
              borderColor: status.ok ? "color-mix(in srgb, var(--success) 30%, transparent)" : "color-mix(in srgb, var(--danger) 30%, transparent)"
            }}>
              <Icon name={status.ok ? "check" : "alert"} style={{ color: status.ok ? "var(--success)" : "var(--danger)" }} />
              <span>{status.ok
                ? <><b>Reachable.</b> {api.host()} answered <code>GET /health</code> with {status.status}.</>
                : status.demo ? "Enter a base URL above, save, then test." : <><b>Not reachable.</b> {status.error || `Server returned ${status.status}.`}</>}</span>
            </div>
          )}
        </div>
      </div>
      </fieldset>

      <div className="section-intro" style={{ marginTop: 8, marginBottom: 0 }}>
        <h2 style={{ fontSize: 18 }}>API contract</h2>
        <p>Implement these JSON endpoints on your backend. The shapes below are exactly what this UI sends and expects.</p>
      </div>

      {ENDPOINTS.map(ep => (
        <div className="card" key={ep.path}>
          <div className="card-head">
            <span className="pill info" style={{ fontFamily: "var(--font-mono)" }}>{ep.method}</span>
            <code style={{ fontSize: 13 }}>{"{base}" + ep.path}</code>
          </div>
          <div className="card-body fgroup">
            <div className="muted" style={{ fontSize: 13, marginTop: -4 }}>{ep.desc}</div>
            <div className="frow" style={{ alignItems: "start" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--text-muted)" }}>Request body</div>
                <CodeBlock title="application/json" dots={false} value={jsonStr(api.SAMPLES[ep.key].request)} />
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--text-muted)" }}>200 response</div>
                <CodeBlock title="application/json" dots={false} value={jsonStr(api.SAMPLES[ep.key].response)} />
              </div>
            </div>

            {ep.key === "generate" && (
              <div className="warn-strip" style={{ background: "var(--surface-3)", borderColor: "var(--border)", flexDirection: "column", alignItems: "stretch", gap: 12 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <Icon name="history" style={{ color: "var(--accent)" }} />
                  <span><b>Slow generation?</b> Answer <code>202</code> with a job, and the UI will poll <code>GET {"{base}"}/csr/jobs/{"{jobId}"}</code> until it's <code>done</code> — showing a live progress stepper.</span>
                </div>
                <div className="frow" style={{ alignItems: "start" }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--text-muted)" }}>202 Accepted</div>
                    <CodeBlock title="application/json" dots={false} value={jsonStr(api.SAMPLES.generateAsync.response)} />
                  </div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--text-muted)" }}>Job poll · processing → done</div>
                    <CodeBlock title="GET /csr/jobs/{jobId}" dots={false}
                      value={jsonStr(api.SAMPLES.job.processing) + "\n\n" + jsonStr(api.SAMPLES.job.done)} />
                  </div>
                </div>
              </div>
            )}

            <CodeBlock title="curl" cmd dots={false} value={curl(ep)}
              onCopy={() => copyText(curl(ep)).then(() => push("curl copied"))} />
          </div>
        </div>
      ))}

      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="alert" /></span>
          <div><h3>Errors</h3><div className="desc">Any non-2xx response is shown to the user.</div></div>
        </div>
        <div className="card-body fgroup">
          <div className="muted" style={{ fontSize: 13 }}>Return an <code>error</code> object. Include <code>fields</code> to attach validation messages to specific inputs (<code>commonName</code>, <code>email</code>, <code>country</code>).</div>
          <CodeBlock title="4xx / 5xx · application/json" dots={false}
            value={jsonStr({ error: { message: "Common Name is required.", fields: { commonName: "This field can't be empty." } } })} />
        </div>
      </div>
    </div>
  );
}
