/* Paste & inspect an existing CSR (ported from design views-decode.jsx) */
import React, { useState } from "react";
import { Icon, Field, Button, Pill } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import * as engine from "../lib/engine.js";

const SAMPLE_CSR_HINT = "Paste a PEM-encoded CSR beginning with -----BEGIN CERTIFICATE REQUEST-----";

export function DecodeView({ push }) {
  const [text, setText] = useState("");
  const [keyText, setKeyText] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [decoded, setDecoded] = useState(null);
  const [match, setMatch] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function run(input, keyInput) {
    const pem = (input != null ? input : text).trim();
    const kpem = (keyInput != null ? keyInput : keyText).trim();
    setErr(""); setDecoded(null); setMatch(null);
    if (!pem) { setErr("Paste a CSR first."); return; }
    if (!/BEGIN CERTIFICATE REQUEST/.test(pem)) {
      setErr("This doesn't look like a CSR. It should start with “-----BEGIN CERTIFICATE REQUEST-----”."); return;
    }
    setBusy(true);
    try {
      const res = await api.decode(pem);
      setDecoded(res);
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
          </div>
        )}
      </div>
    </div>
  );
}
