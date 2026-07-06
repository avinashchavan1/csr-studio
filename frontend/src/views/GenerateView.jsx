/* CSR generation form + output (ported from design views-generate.jsx) */
import React, { useState, useEffect, useRef } from "react";
import { Icon, Field, TextInput, Select, Segmented, Button, CodeBlock, Pill } from "../components/ui.jsx";
import { COUNTRIES, KEY_PRESETS, HASHES, PRESETS, PQC_ALGOS, classifySAN, isValidDomain, copyText, download, safeName } from "../lib/data.js";
import * as engine from "../lib/engine.js";
import * as api from "../lib/api.js";

function strengthFor(keyType, size) {
  if (keyType === "pqc") {
    return { lvl: 4, label: "Post-quantum", note: (size || "") + " · resistant to quantum attacks" };
  }
  if (keyType === "ed25519") {
    return { lvl: 4, label: "Very strong", note: "Ed25519 · modern EdDSA, fast & compact" };
  }
  if (keyType === "ecdsa") {
    if (size === "P-521") return { lvl: 4, label: "Very strong", note: "ECDSA P-521 · ~256-bit security" };
    return size === "P-384"
      ? { lvl: 4, label: "Very strong", note: "ECDSA P-384 · ~192-bit security" }
      : { lvl: 4, label: "Strong · modern", note: "ECDSA P-256 · ~128-bit, fast handshakes" };
  }
  const b = parseInt(size, 10);
  if (b >= 4096) return { lvl: 4, label: "Very strong", note: "RSA 4096 · maximum compatibility margin" };
  if (b >= 3072) return { lvl: 4, label: "Very strong", note: "RSA 3072 · ~128-bit security" };
  return { lvl: 3, label: "Strong", note: "RSA 2048 · the industry standard" };
}

export function emptyForm() {
  return {
    cn: "", sans: [], O: "", OU: "", L: "", ST: "", C: "US", email: "",
    keyType: "rsa", size: "2048", hash: "SHA-256", keyFormat: "pkcs8",
    eku: [], ku: [], bcCa: false, bcPathLen: "", sanType: "AUTO", rsaPss: false,
    pqcAlgo: "ML-DSA-65"
  };
}

const GEN_STEPS = [
  { key: "submit", name: "Request submitted", meta: "sent to the server" },
  { key: "queued", name: "Queued", meta: "accepted, awaiting a worker" },
  { key: "keygen", name: "Generating key pair", meta: "creating the private key" },
  { key: "sign", name: "Signing request", meta: "building & signing the CSR" },
  { key: "ready", name: "CSR ready", meta: "delivered to your browser" }
];
function stageOf(p) {
  if (!p) return 0;
  if (p.phase === "submitting") return 0;
  if (p.phase === "queued") return 1;
  if (p.phase === "processing") return /sign/i.test((p.status || "") + " " + (p.label || "")) ? 3 : 2;
  if (p.phase === "done") return 5;
  return 0;
}

function ProgressStepper({ progress, elapsed, form }) {
  const maxRef = useRef(0);
  const p = progress || {};
  if (p.phase === "retrying") { /* hold position */ }
  else maxRef.current = Math.max(maxRef.current, stageOf(p));
  const stage = maxRef.current;
  const isAsync = stage >= 1 || p.phase === "queued" || p.phase === "processing";
  const retrying = p.phase === "retrying";
  const demo = api.mode() === "demo";

  if (!isAsync) {
    return (
      <div className="result-empty">
        <span className="big"><span className="spinner" style={{ width: 26, height: 26, borderColor: "var(--accent-ring)", borderTopColor: "var(--accent)" }} /></span>
        <h4>{demo ? "Generating " + (form.keyType === "ecdsa" ? "EC" : "RSA " + form.size + "-bit") + " key pair…" : "Generating on " + api.host() + "…"}</h4>
        <p>{retrying ? "Connection issue — retrying…" : (form.keyType === "rsa" && parseInt(form.size) >= 4096 ? "4096-bit keys take a few seconds." : "Working on it…")} · {elapsed.toFixed(1)}s</p>
        {retrying && <div className="retry-note" style={{ marginTop: 14 }}><Icon name="refresh" />Retrying{p.attempt ? " (attempt " + p.attempt + ")" : ""}…</div>}
      </div>
    );
  }

  return (
    <div className="progress-card fade-in">
      <div className="progress-head">
        <span className="ph-ico"><Icon name="server" /></span>
        <div>
          <h4>{demo ? "Generating your CSR" : "Generating on " + api.host()}</h4>
          <div className="ph-sub">{p.jobId ? "job " + p.jobId : "async job"}{typeof p.progress === "number" ? " · " + Math.round(p.progress * 100) + "%" : ""}</div>
        </div>
        <span className="ph-time">{elapsed.toFixed(1)}s</span>
      </div>
      <div className="steps-v">
        {GEN_STEPS.map((s, i) => {
          const done = stage > i;
          const active = stage === i;
          return (
            <div key={s.key} className={"step-v" + (done ? " done" : active ? " active" : "")}>
              <div className="sv-rail">
                <div className="sv-dot">
                  {done ? <Icon name="check" /> : active ? <span className="sv-spin" /> : null}
                </div>
                <div className="sv-line" />
              </div>
              <div className="sv-body">
                <div className="sv-name">{s.name}</div>
                <div className="sv-meta">{active && p.label ? p.label : s.meta}</div>
              </div>
            </div>
          );
        })}
      </div>
      {retrying && <div className="retry-note"><Icon name="refresh" />Connection hiccup — retrying{p.attempt ? " (attempt " + p.attempt + ")" : ""}…</div>}
    </div>
  );
}

export function GenerateView({ seed, onGenerated, push }) {
  const [f, setF] = useState(() => seed ? { ...emptyForm(), ...seed } : emptyForm());
  const [sanInput, setSanInput] = useState("");
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [result, setResult] = useState(null);
  const [p12pass, setP12pass] = useState("");
  const resultRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => { if (seed) { setF({ ...emptyForm(), ...seed }); setResult(null); } }, [seed]);
  useEffect(() => () => clearInterval(timerRef.current), []);

  const set = (k, v) => setF(p => ({ ...p, [k]: v }));
  const setKeyType = (kt) => setF(p => ({
    ...p, keyType: kt, size: kt === "ecdsa" ? "P-256" : kt === "rsa" ? "2048" : ""
  }));
  const strengthSize = f.keyType === "pqc" ? f.pqcAlgo : f.size;

  const addSan = () => {
    let raw = sanInput.trim();
    // Only strip scheme/path for host-like types, not for URI/email SANs.
    if (f.sanType === "AUTO" || f.sanType === "DNS" || f.sanType === "IP") {
      raw = raw.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    }
    if (!raw) return;
    const type = f.sanType === "AUTO" ? classifySAN(raw) : f.sanType;
    if (f.sans.some(s => s.value.toLowerCase() === raw.toLowerCase())) { setSanInput(""); return; }
    set("sans", [...f.sans, { type, value: raw }]);
    setSanInput("");
  };
  const removeSan = (i) => set("sans", f.sans.filter((_, idx) => idx !== i));

  const applyPreset = (p) => {
    const out = p.apply(f.cn);
    setF(prev => ({
      ...prev,
      ...(out.cn !== undefined ? { cn: out.cn } : {}),
      sans: out.sans && out.sans.length
        ? [...prev.sans.filter(s => !out.sans.some(n => n.value === s.value)), ...out.sans]
        : prev.sans
    }));
    push("Preset applied — " + p.title);
  };

  const cnChip = f.cn ? { type: classifySAN(f.cn), value: f.cn, locked: true } : null;
  const allSans = (cnChip ? [cnChip] : []).concat(f.sans);

  const subject = () => ({
    CN: f.cn.trim(), O: f.O.trim(), OU: f.OU.trim(), L: f.L.trim(),
    ST: f.ST.trim(), C: f.C, email: f.email.trim()
  });
  const opts = () => ({
    subject: subject(),
    sans: allSans.map(s => ({ type: s.type, value: s.value })),
    keyType: f.keyType, size: f.size, hash: f.hash, keyFormat: f.keyFormat,
    keyUsage: f.ku, eku: f.eku,
    bcCa: f.bcCa, bcPathLen: f.bcPathLen, rsaPss: f.rsaPss, pqcAlgo: f.pqcAlgo
  });

  const toggle = (field, val) =>
    set(field, f[field].includes(val) ? f[field].filter(x => x !== val) : [...f[field], val]);

  const cmd = engine.opensslCommand(opts());
  const strength = strengthFor(f.keyType, strengthSize);

  function validate() {
    const e = {};
    if (f.cn.trim() && !isValidDomain(f.cn.trim())) e.cn = "That doesn't look like a valid hostname.";
    else if (!f.cn.trim() && f.sans.length === 0) e.cn = "Enter a Common Name, or add at least one SAN below.";
    if (f.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email.trim())) e.email = "Enter a valid email address.";
    if (f.C && f.C.length !== 2) e.C = "Country must be a 2-letter code.";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function generate() {
    if (!validate()) { push("Please fix the highlighted fields.", "err"); return; }
    setBusy(true); setResult(null); setProgress({ phase: "submitting" }); setElapsed(0);
    const t0 = Date.now();
    clearInterval(timerRef.current);
    timerRef.current = setInterval(() => setElapsed((Date.now() - t0) / 1000), 100);
    try {
      const res = await api.generate(opts(), { onProgress: (p) => setProgress(p) });
      setResult(res);
      onGenerated && onGenerated(res);
      push(api.mode() === "demo" ? "CSR generated (demo)" : "CSR generated on " + api.host());
    } catch (err) {
      console.error(err);
      if (err.fields) {
        const map = { commonName: "cn", email: "email", country: "C" };
        const e = {};
        Object.keys(err.fields).forEach(k => { e[map[k] || k] = err.fields[k]; });
        setErrors(e);
      }
      push(err.message || "Generation failed", "err");
    } finally {
      clearInterval(timerRef.current);
      setBusy(false); setProgress(null);
    }
  }

  async function genSelfSigned() {
    if (!validate()) { push("Please fix the highlighted fields.", "err"); return; }
    setBusy(true); setResult(null); setProgress({ phase: "submitting" }); setElapsed(0);
    const t0 = Date.now();
    clearInterval(timerRef.current);
    timerRef.current = setInterval(() => setElapsed((Date.now() - t0) / 1000), 100);
    try {
      const res = await api.selfSigned(opts());
      setResult(res);
      onGenerated && onGenerated(res);
      push("Self-signed certificate issued on " + api.host());
    } catch (err) {
      console.error(err);
      push(err.message || "Self-signed generation failed", "err");
    } finally {
      clearInterval(timerRef.current);
      setBusy(false); setProgress(null);
    }
  }

  async function downloadP12() {
    if (!p12pass) { push("Set an export password for the .p12 bundle.", "err"); return; }
    try {
      const blob = await api.pkcs12({ certificatePem: result.certPem, privateKeyPem: result.keyPem, password: p12pass, alias: safeName(f.cn) });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = safeName(f.cn) + ".p12";
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      push("PKCS#12 (.p12) downloaded");
    } catch (e) { push(e.message || "PKCS#12 bundling failed", "err"); }
  }

  async function genHybrid() {
    if (f.keyType === "pqc") { push("Pick a classical key (RSA/ECDSA/Ed25519); the PQC half is added automatically.", "err"); return; }
    if (!validate()) { push("Please fix the highlighted fields.", "err"); return; }
    setBusy(true); setResult(null); setProgress({ phase: "submitting" }); setElapsed(0);
    const t0 = Date.now();
    clearInterval(timerRef.current);
    timerRef.current = setInterval(() => setElapsed((Date.now() - t0) / 1000), 100);
    try {
      const res = await api.hybrid(opts(), "ML-DSA-65");
      setResult({ hybrid: res, subject: res.classical.subject, sans: res.classical.sans });
      onGenerated && onGenerated(res.classical);
      push("Hybrid pair generated — classical + ML-DSA-65");
    } catch (err) {
      console.error(err);
      push(err.message || "Hybrid generation failed", "err");
    } finally {
      clearInterval(timerRef.current);
      setBusy(false); setProgress(null);
    }
  }

  async function shareCsr(pem) {
    try {
      const s = await api.shareCreate(pem);
      const link = location.origin + "/?share=" + s.id;
      await copyText(link);
      push("Review link copied to clipboard");
    } catch (e) { push(e.message || "Couldn't create link", "err"); }
  }

  function reset() { setF(emptyForm()); setResult(null); setErrors({}); setP12pass(""); }

  const doCopy = (text, what) => copyText(text).then(() => push(what + " copied")).catch(() => push("Copy failed", "err"));
  const fileBase = safeName(f.cn);

  return (
    <div className="grid-2 fade-in">
      {/* form column */}
      <div className="stack">
        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="spark" /></span>
            <div><h3>Quick start</h3><div className="desc">Pre-fill a common certificate shape, then tweak below.</div></div>
          </div>
          <div className="card-body">
            <div className="presets">
              {PRESETS.map(p => (
                <button key={p.id} className="preset" onClick={() => applyPreset(p)}>
                  <span className="pt"><Icon name={p.icon} />{p.title}</span>
                  <span className="pd">{p.desc}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="globe" /></span>
            <div><h3>Domain &amp; subject</h3><div className="desc">Identity details embedded in the certificate.</div></div>
            <span className="card-num">01</span>
          </div>
          <div className="card-body fgroup">
            <Field label="Common Name (CN)" optional hint="The primary domain. Optional — modern certs can be SAN-only (just add a SAN below)." error={errors.cn}>
              <TextInput mono value={f.cn} onChange={v => set("cn", v)} error={errors.cn} placeholder="example.com" onBlur={validate} />
            </Field>

            <Field label="Subject Alternative Names (SAN)" hint="Add every extra hostname or IP. The CN is included automatically.">
              <div className="input-row">
                <div style={{ width: 104, flex: "none" }}>
                  <Select value={f.sanType} onChange={v => set("sanType", v)}
                    options={[{ value: "AUTO", label: "Auto" }, { value: "DNS", label: "DNS" }, { value: "IP", label: "IP" }, { value: "EMAIL", label: "Email" }, { value: "URI", label: "URI" }]} />
                </div>
                <input className="input mono" value={sanInput} placeholder="www.example.com, api.example.com, 203.0.113.10"
                  onChange={e => setSanInput(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter" || e.key === ",") { e.preventDefault(); addSan(); } }} />
                <Button variant="soft" icon="plus" onClick={addSan}>Add</Button>
              </div>
              <div className="chips" style={{ marginTop: 4 }}>
                {allSans.length === 0 && <span className="chip empty">No alternative names yet</span>}
                {allSans.map((s, i) => (
                  <span key={s.value + i} className="chip">
                    <span className={"tag " + (s.locked ? "cn" : s.type === "IP" ? "ip" : "")}>{s.locked ? "CN" : s.type}</span>
                    {s.value}
                    {!s.locked && <button onClick={() => removeSan(i - (cnChip ? 1 : 0))} aria-label="remove"><Icon name="x" /></button>}
                  </span>
                ))}
              </div>
            </Field>

            <div className="frow">
              <Field label="Organization (O)" optional><TextInput value={f.O} onChange={v => set("O", v)} placeholder="Acme Inc." /></Field>
              <Field label="Organizational Unit (OU)" optional><TextInput value={f.OU} onChange={v => set("OU", v)} placeholder="IT / DevOps" /></Field>
            </div>
            <div className="frow-3">
              <Field label="City / Locality (L)" optional><TextInput value={f.L} onChange={v => set("L", v)} placeholder="San Francisco" /></Field>
              <Field label="State / Province (ST)" optional><TextInput value={f.ST} onChange={v => set("ST", v)} placeholder="California" /></Field>
              <Field label="Country (C)" error={errors.C}>
                <Select value={f.C} onChange={v => set("C", v)} options={COUNTRIES.map(c => ({ value: c.code, label: `${c.code} — ${c.name}` }))} />
              </Field>
            </div>
            <Field label="Email" optional error={errors.email}>
              <TextInput value={f.email} onChange={v => set("email", v)} placeholder="admin@example.com" />
            </Field>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="key" /></span>
            <div><h3>Key &amp; algorithm</h3><div className="desc">How the private key is generated and the request is signed.</div></div>
            <span className="card-num">02</span>
          </div>
          <div className="card-body fgroup">
            <Field label="Key algorithm">
              <Segmented value={f.keyType} onChange={setKeyType}
                options={[{ value: "rsa", label: "RSA" }, { value: "ecdsa", label: "ECDSA" }, { value: "ed25519", label: "Ed25519" }, { value: "pqc", label: "PQC" }]} />
            </Field>
            {f.keyType === "pqc" ? (
              <Field label="Post-quantum algorithm"
                hint="NIST post-quantum signature scheme. Keys are PKCS#8; the scheme fixes the hash, so there's nothing else to choose.">
                <Select value={f.pqcAlgo} onChange={v => set("pqcAlgo", v)} options={PQC_ALGOS} />
              </Field>
            ) : f.keyType === "ed25519" ? (
              <div className="warn-strip" style={{ background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
                <Icon name="info" style={{ color: "var(--accent)" }} />
                <span>Ed25519 uses a fixed curve and the <b>EdDSA</b> signature scheme — no key size or hash to choose. Key is emitted as PKCS#8.</span>
              </div>
            ) : (
              <>
                <div className="frow">
                  <Field label={f.keyType === "ecdsa" ? "Curve" : "Key size"}>
                    <Select value={f.size} onChange={v => set("size", v)} options={KEY_PRESETS[f.keyType]} />
                  </Field>
                  <Field label="Signature hash"><Select value={f.hash} onChange={v => set("hash", v)} options={HASHES} /></Field>
                </div>
                <Field label="Private key format"
                  hint={f.keyType === "ecdsa"
                    ? "Elliptic-curve keys are always emitted as PKCS#8 (“BEGIN PRIVATE KEY”)."
                    : "PKCS#8 is the modern default. PKCS#1 is the traditional “BEGIN RSA PRIVATE KEY” format some older servers expect."}>
                  {f.keyType === "ecdsa"
                    ? <div className="seg" style={{ opacity: .6, pointerEvents: "none" }}><button className="on">PKCS#8</button></div>
                    : <Segmented value={f.keyFormat} onChange={v => set("keyFormat", v)}
                        options={[{ value: "pkcs8", label: "PKCS#8" }, { value: "pkcs1", label: "PKCS#1 (traditional)" }]} />}
                </Field>
                {f.keyType === "rsa" && (
                  <Field label="Signature scheme"
                    hint="RSA-PSS (RSASSA-PSS) is the modern probabilistic scheme; PKCS#1 v1.5 is the legacy default with the widest compatibility.">
                    <Segmented value={f.rsaPss ? "pss" : "pkcs1v15"} onChange={v => set("rsaPss", v === "pss")}
                      options={[{ value: "pkcs1v15", label: "PKCS#1 v1.5" }, { value: "pss", label: "RSA-PSS" }]} />
                  </Field>
                )}
              </>
            )}
            <Field label="Certificate usage" optional
              hint="X.509 extensions requested in the CSR. Public CAs usually set these themselves; handy for internal CAs that honour them.">
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div>
                  <div className="hint" style={{ marginBottom: 5 }}>Extended key usage</div>
                  <div className="chips">
                    {[["serverAuth", "TLS Server"], ["clientAuth", "TLS Client"], ["codeSigning", "Code signing"], ["emailProtection", "Email"]].map(([v, l]) => (
                      <button key={v} type="button" className={"chip" + (f.eku.includes(v) ? "" : " empty")}
                        style={{ cursor: "pointer" }} onClick={() => toggle("eku", v)}>{l}</button>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="hint" style={{ marginBottom: 5 }}>Key usage</div>
                  <div className="chips">
                    {[["digitalSignature", "Digital signature"], ["keyEncipherment", "Key encipherment"], ["dataEncipherment", "Data encipherment"], ["keyAgreement", "Key agreement"]].map(([v, l]) => (
                      <button key={v} type="button" className={"chip" + (f.ku.includes(v) ? "" : " empty")}
                        style={{ cursor: "pointer" }} onClick={() => toggle("ku", v)}>{l}</button>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="hint" style={{ marginBottom: 5 }}>Basic constraints</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <button type="button" className={"chip" + (f.bcCa ? "" : " empty")}
                      style={{ cursor: "pointer" }} onClick={() => set("bcCa", !f.bcCa)}>CA certificate</button>
                    {f.bcCa && (
                      <input className="input mono" style={{ width: 150 }} placeholder="path length (opt.)"
                        value={f.bcPathLen} onChange={e => set("bcPathLen", e.target.value.replace(/[^0-9]/g, ""))} />
                    )}
                  </div>
                </div>
              </div>
            </Field>

            <div className="strength">
              <div className={"strength s" + strength.lvl}>
                <div className="strength-bar"><i></i><i></i><i></i><i></i></div>
              </div>
              <div className="strength-row">
                <span className="lbl">{strength.note}</span>
                <span className="val" style={{ color: "var(--accent)" }}>{strength.label}</span>
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="primary" size="lg" icon={busy ? null : "cert"} loading={busy} onClick={generate} style={{ flex: 1 }}>
            {busy ? "Working…" : "Generate CSR & private key"}
          </Button>
          <Button variant="ghost" size="lg" icon="spark" onClick={genHybrid} disabled={busy || f.keyType === "pqc"}
            title="Generate a matched classical + ML-DSA (post-quantum) pair">Hybrid PQC</Button>
          <Button variant="ghost" size="lg" icon="shield" onClick={genSelfSigned} disabled={busy}
            title="Generate a self-signed test certificate (connected mode)">Self-signed cert</Button>
          <Button variant="ghost" size="lg" icon="refresh" onClick={reset} title="Reset form" />
        </div>
      </div>

      {/* output column */}
      <div className="stack" ref={resultRef} style={{ position: "sticky", top: 92 }}>
        <CodeBlock title="openssl — equivalent command" cmd value={cmd} onCopy={() => doCopy(cmd, "Command")} dots={true} />

        {!result && !busy && (
          <div className="result-empty">
            <span className="big"><Icon name="cert" /></span>
            <h4>Your CSR will appear here</h4>
            <p>Add a Common Name or at least one SAN, then generate. Your backend signs the request and returns it here.</p>
          </div>
        )}

        {busy && <ProgressStepper progress={progress} elapsed={elapsed} form={f} />}

        {result && result.hybrid && (
          <div className="stack fade-in">
            <div className="warn-strip" style={{ background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
              <Icon name="spark" style={{ color: "var(--accent)" }} />
              <span><b>Hybrid pair for the same identity.</b> Submit the <b>classical</b> CSR to your CA today; keep the <b>ML-DSA</b> (post-quantum) one for crypto-agility as PQC issuance rolls out. Two independent private keys — store both safely.</span>
            </div>
            {[["classical", result.hybrid.classical, "Classical"], ["pqc", result.hybrid.pqc, "Post-quantum"]].map(([k, r, label]) => (
              <div className="card" key={k}>
                <div className="card-head"><span className="ico"><Icon name={k === "pqc" ? "key" : "cert"} /></span>
                  <div><h3>{label} — {r.keyLabel}</h3></div>
                  <span style={{ marginLeft: "auto" }}><Button variant="ghost" size="sm" icon="arrow" onClick={() => shareCsr(r.csrPem)}>Share</Button></span>
                </div>
                <div className="card-body stack">
                  <CodeBlock title={fileBase + "-" + k + ".csr"} value={r.csrPem}
                    onCopy={() => doCopy(r.csrPem, "CSR")}
                    onDownload={() => { download(fileBase + "-" + k + ".csr", r.csrPem); push("CSR downloaded"); }} />
                  <CodeBlock title={fileBase + "-" + k + ".key — private key"} value={r.keyPem}
                    onCopy={() => doCopy(r.keyPem, "Private key")}
                    onDownload={() => { download(fileBase + "-" + k + ".key", r.keyPem); push("Private key downloaded"); }} />
                </div>
              </div>
            ))}
          </div>
        )}

        {result && !result.hybrid && (
          <div className="stack fade-in">
            <div className="warn-strip">
              <Icon name="lock" />
              <span>{api.mode() === "demo"
                ? <><b>Keep the private key secret.</b> In demo mode it is generated in your browser. Once your backend is connected it will be created on the server and delivered over the API. Either way — store it safely; you can't recover it later.</>
                : <><b>Keep the private key secret.</b> It was generated on <b>{api.host()}</b> and delivered over the API. Store it somewhere safe and keep it out of transit/access logs — you can't recover it later.</>}</span>
            </div>

            <CodeBlock title={fileBase + ".csr — certificate signing request"} value={result.csrPem}
              onCopy={() => doCopy(result.csrPem, "CSR")}
              onDownload={() => { download(fileBase + ".csr", result.csrPem); push("CSR downloaded"); }} />
            <div style={{ marginTop: -10 }}>
              <Button variant="soft" size="sm" icon="arrow" onClick={() => shareCsr(result.csrPem)}
                title="Create a read-only link to share this CSR for review">Share for review</Button>
            </div>

            {result.recordPath && (
              <div style={{ marginTop: -4, display: "flex", alignItems: "center", gap: 8, fontSize: 13, flexWrap: "wrap" }}>
                <Icon name="globe" />
                <span style={{ color: "var(--muted)" }}>Permalink</span>
                <code style={{ wordBreak: "break-all" }}>{location.origin + result.recordPath}</code>
                <Button variant="ghost" size="sm" icon="copy"
                  onClick={() => doCopy(location.origin + result.recordPath, "Permalink")}
                  title="Copy the retrievable link to this CSR (read-only, no private key)">Copy</Button>
              </div>
            )}

            <CodeBlock title={fileBase + ".key — private key (" + (result.keyFormat || "PKCS#8") + ")"} value={result.keyPem}
              onCopy={() => doCopy(result.keyPem, "Private key")}
              onDownload={() => { download(fileBase + ".key", result.keyPem); push("Private key downloaded"); }} />

            {result.certPem && (
              <>
                <div className="warn-strip">
                  <Icon name="info" />
                  <span><b>Self-signed test certificate.</b> Issued by this key itself — browsers won't trust it. Use for local/dev testing; submit the CSR to a real CA for a trusted certificate.</span>
                </div>
                <CodeBlock title={fileBase + ".crt — self-signed certificate"} value={result.certPem}
                  onCopy={() => doCopy(result.certPem, "Certificate")}
                  onDownload={() => { download(fileBase + ".crt", result.certPem); push("Certificate downloaded"); }} />

                <div className="card">
                  <div className="card-head"><span className="ico"><Icon name="lock" /></span><h3>PKCS#12 bundle (.p12)</h3>
                    <span className="card-num">cert + key</span>
                  </div>
                  <div className="card-body" style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
                    <div style={{ flex: 1, minWidth: 200 }}>
                      <Field label="Export password" hint="Protects the .p12; you'll enter it when importing into a server or keystore.">
                        <TextInput type="password" value={p12pass} onChange={setP12pass} placeholder="choose a password" />
                      </Field>
                    </div>
                    <Button variant="primary" icon="download" onClick={downloadP12}>Download .p12</Button>
                  </div>
                </div>
              </>
            )}

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="info" /></span><h3>Summary</h3>
                <span style={{ marginLeft: "auto" }}><Pill kind="ok" icon="check">Valid PKCS#10</Pill></span>
              </div>
              <div className="card-body">
                <dl className="meta">
                  <dt>Common Name</dt><dd>{result.subject.CN}</dd>
                  <dt>Alt names</dt><dd>{result.sans.length ? result.sans.map(s => s.value).join(", ") : <span className="empty">none</span>}</dd>
                  <dt>Key</dt><dd>{result.keyLabel}</dd>
                  <dt>Signature</dt><dd>{result.sigAlg}</dd>
                  <dt>Organization</dt><dd>{result.subject.O || <span className="empty">—</span>}</dd>
                  <dt>Country</dt><dd>{result.subject.C || <span className="empty">—</span>}</dd>
                </dl>
              </div>
            </div>

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="arrow" /></span><h3>What's next</h3></div>
              <div className="card-body">
                <ol className="steps">
                  <li><b>Submit the CSR</b> — paste the <code>.csr</code> into your certificate authority (Let's Encrypt, DigiCert, Sectigo, your internal CA…) to get a signed certificate.</li>
                  <li><b>Keep the <code>.key</code> private</b> — it stays on your server and is never uploaded to the CA. Store it somewhere safe and access-controlled.</li>
                  <li><b>Install both</b> — once issued, deploy the certificate together with this private key on your web server or load balancer.</li>
                </ol>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
