/* Paste & inspect an existing CSR (ported from design views-decode.jsx) */
import React, { useState, useEffect } from "react";
import { Icon, Field, Button, Pill } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import * as engine from "../lib/engine.js";

const SAMPLE_CSR_HINT = "Paste a PEM-encoded CSR beginning with -----BEGIN CERTIFICATE REQUEST-----";

export function DecodeView({ push, seedCsr }) {
  const [text, setText] = useState("");
  const [keyText, setKeyText] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [decoded, setDecoded] = useState(null);
  const [match, setMatch] = useState(null);
  const [lint, setLint] = useState(null);
  const [quantum, setQuantum] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => { if (seedCsr) { setText(seedCsr); run(seedCsr); } /* eslint-disable-next-line */ }, [seedCsr]);

  async function run(input, keyInput) {
    const pem = (input != null ? input : text).trim();
    const kpem = (keyInput != null ? keyInput : keyText).trim();
    setErr(""); setDecoded(null); setMatch(null); setLint(null); setQuantum(null);
    if (!pem) { setErr("Paste a CSR first."); return; }
    if (!/BEGIN CERTIFICATE REQUEST/.test(pem)) {
      setErr("This doesn't look like a CSR. It should start with “-----BEGIN CERTIFICATE REQUEST-----”."); return;
    }
    setBusy(true);
    try {
      const res = await api.decode(pem);
      setDecoded(res);
      api.lint(pem).then(setLint).catch(() => {});
      api.quantumScan({ csr: pem }).then(setQuantum).catch(() => {});
      if (kpem) {
        // Key match runs entirely in-browser (node-forge) — the private key is
        // NEVER sent to the server, so the "compared locally" promise holds.
        try { setMatch(engine.keyMatch(pem, kpem)); }
        catch (e) { setMatch({ supported: false, msg: e.message || "Couldn't compare the key pair." }); }
      }
      push(api.mode() === "demo" ? "CSR decoded (demo)" : "CSR decoded on " + api.host());
    } catch (e) {
      console.error(e);
      setErr(e.message || "Couldn't parse this CSR. It may be malformed, or use a key type the server can't read.");
    } finally {
      setBusy(false);
    }
  }

  async function generateSample() {
    push("Building a sample CSR…");
    try {
      const res = await api.generate({
        subject: { CN: "example.com", O: "Example Corp", OU: "Web", L: "San Francisco", ST: "California", C: "US", email: "" },
        sans: [{ type: "DNS", value: "example.com" }, { type: "DNS", value: "www.example.com" }, { type: "DNS", value: "api.example.com" }],
        keyType: "rsa", size: "2048", hash: "SHA-256", keyFormat: "pkcs8"
      });
      setText(res.csrPem); setKeyText(res.keyPem); setShowKey(true);
      run(res.csrPem, res.keyPem);
    } catch (e) { push("Couldn't build sample", "err"); }
  }

  const subjLabels = [["CN", "Common Name"], ["O", "Organization"], ["OU", "Org. Unit"], ["L", "Locality"], ["ST", "State"], ["C", "Country"], ["email", "Email"]];

  return (
    <>
    {seedCsr && (
      <div className="warn-strip" style={{ marginBottom: 18, background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
        <Icon name="eye" style={{ color: "var(--accent)" }} />
        <span><b>Shared for review.</b> This CSR was opened from a review link (read-only). Check the subject, SANs and quantum readiness below before it's submitted to a CA.</span>
      </div>
    )}
    <div className="grid-2 fade-in">
      <div className="stack">
        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="search" /></span>
            <div><h3>Paste a CSR</h3><div className="desc">Decode and verify any PKCS#10 certificate signing request.</div></div>
          </div>
          <div className="card-body fgroup">
            <Field error={err}>
              <textarea className={"input mono" + (err ? " err" : "")} value={text}
                onChange={e => setText(e.target.value)} placeholder={SAMPLE_CSR_HINT}
                style={{ minHeight: 220 }} spellCheck={false} />
            </Field>

            {!showKey
              ? <button className="btn-link" style={{ alignSelf: "flex-start" }} onClick={() => setShowKey(true)}>
                  <Icon name="plus" style={{ width: 13, height: 13, verticalAlign: "-2px", marginRight: 4 }} />
                  Also check a private key matches this CSR
                </button>
              : <Field label="Private key" optional hint="RSA only. Paste the matching key to confirm it belongs to this CSR — it's compared locally, never sent anywhere.">
                  <textarea className="input mono" value={keyText}
                    onChange={e => setKeyText(e.target.value)} placeholder="-----BEGIN PRIVATE KEY----- (optional)"
                    style={{ minHeight: 120 }} spellCheck={false} />
                </Field>}

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <Button variant="primary" icon="eye" loading={busy} onClick={() => run()}>Decode &amp; verify</Button>
              <Button variant="ghost" icon="spark" onClick={generateSample}>Load a sample</Button>
              {(text || keyText) && <Button variant="ghost" icon="x" onClick={() => { setText(""); setKeyText(""); setDecoded(null); setMatch(null); setErr(""); }}>Clear</Button>}
            </div>
          </div>
        </div>
      </div>

      <div className="stack" style={{ position: "sticky", top: 92 }}>
        {!decoded && !busy && (
          <div className="result-empty">
            <span className="big"><Icon name="search" /></span>
            <h4>Decoded details appear here</h4>
            <p>See the subject, alternative names, key strength and signature — and confirm the request's self-signature is valid.</p>
          </div>
        )}
        {busy && !decoded && (
          <div className="result-empty">
            <span className="big"><span className="spinner" style={{ width: 26, height: 26, borderColor: "var(--accent-ring)", borderTopColor: "var(--accent)" }} /></span>
            <h4>{api.mode() === "demo" ? "Decoding…" : "Decoding on " + api.host() + "…"}</h4>
            <p>Parsing the request and checking its signature.</p>
          </div>
        )}
        {decoded && (
          <div className="stack fade-in">
            {lint && (
              <div className="card" style={{ borderColor: lint.valid ? "color-mix(in srgb, var(--success) 35%, transparent)" : "color-mix(in srgb, var(--danger) 35%, transparent)" }}>
                <div className="card-head">
                  <span className="ico" style={{ color: lint.valid ? "var(--success)" : "var(--danger)" }}>
                    <Icon name={lint.valid ? "check" : "alert"} />
                  </span>
                  <h3>Compliance check</h3>
                  <span style={{ marginLeft: "auto" }}>
                    {lint.valid
                      ? <Pill kind="ok" icon="check">Passes</Pill>
                      : <Pill kind="warn" icon="alert">{lint.errors.length} issue{lint.errors.length === 1 ? "" : "s"}</Pill>}
                  </span>
                </div>
                <div className="card-body">
                  {lint.errors && lint.errors.length > 0 &&
                    <ul style={{ margin: "0 0 8px", paddingLeft: 18 }}>{lint.errors.map((e, i) => <li key={i} style={{ color: "var(--danger)", fontSize: 13 }}>{e}</li>)}</ul>}
                  {lint.warnings && lint.warnings.length > 0 &&
                    <ul style={{ margin: 0, paddingLeft: 18 }}>{lint.warnings.map((w, i) => <li key={i} style={{ color: "var(--warning)", fontSize: 13 }}>{w}</li>)}</ul>}
                  {(!lint.errors || !lint.errors.length) && (!lint.warnings || !lint.warnings.length) &&
                    <span className="muted" style={{ fontSize: 13 }}>No issues — meets the baseline checks.</span>}
                </div>
              </div>
            )}
            {quantum && (
              <div className="card" style={{ borderColor: quantum.quantumVulnerable ? "color-mix(in srgb, var(--warning) 40%, transparent)" : "color-mix(in srgb, var(--success) 40%, transparent)" }}>
                <div className="card-head">
                  <span className="ico" style={{ color: quantum.quantumVulnerable ? "var(--warning)" : "var(--success)" }}><Icon name="shield" /></span>
                  <h3>Quantum readiness</h3>
                  <span style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center" }}>
                    <span style={{ fontFamily: "var(--font-head)", fontWeight: 700, fontSize: 22, color: quantum.quantumVulnerable ? "var(--warning)" : "var(--success)" }}>{quantum.grade}</span>
                    <Pill kind={quantum.quantumVulnerable ? "warn" : "ok"} icon={quantum.quantumVulnerable ? "alert" : "check"}>
                      {quantum.quantumVulnerable ? "HNDL: " + quantum.hndlRisk : "Quantum-safe"}
                    </Pill>
                  </span>
                </div>
                <div className="card-body stack">
                  <dl className="meta">
                    <dt>Key</dt><dd>{quantum.keyAlgorithm} {quantum.keyDetail}</dd>
                    <dt>Signature</dt><dd>{quantum.signatureAlgorithm || "—"}</dd>
                  </dl>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {quantum.findings.map((x, i) => <li key={i} style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 4 }}>{x}</li>)}
                  </ul>
                  <div className="warn-strip" style={{ background: "var(--accent-soft)", borderColor: "color-mix(in srgb, var(--accent) 24%, transparent)" }}>
                    <Icon name="arrow" style={{ color: "var(--accent)" }} />
                    <span>{quantum.recommendation}</span>
                  </div>
                </div>
              </div>
            )}
            {match && (
              <div className="card" style={{
                borderColor: match.supported
                  ? (match.match ? "color-mix(in srgb, var(--success) 40%, transparent)" : "color-mix(in srgb, var(--danger) 40%, transparent)")
                  : "var(--border)"
              }}>
                <div className="card-head">
                  <span className="ico" style={{ color: match.supported ? (match.match ? "var(--success)" : "var(--danger)") : "var(--text-muted)" }}>
                    <Icon name={match.supported ? (match.match ? "check" : "x") : "info"} />
                  </span>
                  <h3>Private key match</h3>
                  <span style={{ marginLeft: "auto" }}>
                    {!match.supported
                      ? <Pill kind="neutral" icon="info">Not checked</Pill>
                      : match.match
                        ? <Pill kind="ok" icon="check">Key pair matches</Pill>
                        : <Pill kind="warn" icon="alert">Does not match</Pill>}
                  </span>
                </div>
                <div className="card-body">
                  <span className="muted" style={{ fontSize: 13 }}>
                    {!match.supported ? (match.msg || "This key type can't be matched here (RSA only).")
                      : match.match
                        ? `This private key (${match.bits}-bit RSA) corresponds to the public key in the CSR. They're a valid pair.`
                        : "This private key does NOT correspond to the CSR's public key. They were not generated together."}
                  </span>
                </div>
              </div>
            )}

            <div className="card">
              <div className="card-head">
                <span className="ico"><Icon name="shield" /></span><h3>Signature check</h3>
                <span style={{ marginLeft: "auto" }}>
                  {decoded.verified === true
                    ? <Pill kind="ok" icon="check">Signature valid</Pill>
                    : decoded.verified === null
                      ? <Pill kind="info" icon="info">Parsed (EC — not re-checked)</Pill>
                      : <Pill kind="warn" icon="alert">Unverified</Pill>}
                </span>
              </div>
              <div className="card-body">
                <dl className="meta">
                  <dt>Public key</dt><dd>{decoded.keyKind} {decoded.keyDetail || ""}</dd>
                  <dt>Signature</dt><dd>{decoded.sigAlg || "—"}</dd>
                  {decoded.keySha256 && <React.Fragment><dt>Key SHA-256</dt><dd style={{ fontSize: 11, wordBreak: "break-all" }}>{decoded.keySha256}</dd></React.Fragment>}
                  {decoded.keyPin && <React.Fragment><dt>SPKI pin</dt><dd style={{ wordBreak: "break-all" }}>{decoded.keyPin}</dd></React.Fragment>}
                </dl>
              </div>
            </div>

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="globe" /></span><h3>Subject</h3></div>
              <div className="card-body">
                <dl className="meta">
                  {subjLabels.map(([k, lbl]) => (
                    <React.Fragment key={k}>
                      <dt>{lbl}</dt>
                      <dd className={decoded.subject[k] ? "" : "empty"}>{decoded.subject[k] || "—"}</dd>
                    </React.Fragment>
                  ))}
                </dl>
              </div>
            </div>

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="layers" /></span><h3>Alternative names</h3>
                <span className="card-num">{decoded.sans.length}</span>
              </div>
              <div className="card-body">
                {decoded.sans.length === 0
                  ? <span className="muted" style={{ fontSize: 13 }}>No SAN extension present.</span>
                  : <div className="chips">
                      {decoded.sans.map((s, i) => (
                        <span key={i} className="chip"><span className={"tag " + (s.type === "IP" ? "ip" : "")}>{s.type}</span>{s.value}</span>
                      ))}
                    </div>}
              </div>
            </div>

            {decoded.extensions && (decoded.extensions.keyUsage || decoded.extensions.extendedKeyUsage || decoded.extensions.basicConstraints) && (
              <div className="card">
                <div className="card-head"><span className="ico"><Icon name="key" /></span><h3>Requested extensions</h3></div>
                <div className="card-body">
                  <dl className="meta">
                    {decoded.extensions.keyUsage && <React.Fragment><dt>Key usage</dt><dd>{decoded.extensions.keyUsage.join(", ")}</dd></React.Fragment>}
                    {decoded.extensions.extendedKeyUsage && <React.Fragment><dt>Extended key usage</dt><dd>{decoded.extensions.extendedKeyUsage.join(", ")}</dd></React.Fragment>}
                    {decoded.extensions.basicConstraints && <React.Fragment><dt>Basic constraints</dt><dd>{decoded.extensions.basicConstraints}</dd></React.Fragment>}
                  </dl>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
    </>
  );
}
