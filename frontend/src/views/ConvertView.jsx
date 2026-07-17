/* Key Converter — paste any key (or a cert/CSR to pull its public key) and get
   every format back: PKCS#8 / PKCS#1 / SEC1 PEM, DER, public key, JWK, OpenSSH
   line and SPKI fingerprints. Private keys are processed transiently, never stored. */
import React, { useState } from "react";
import { Icon, Field, Button, Pill, CodeBlock } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import { copyText } from "../lib/data.js";

function downloadDer(b64, filename) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

const TYPE_LABEL = {
  "private-key": "Private key", "public-key": "Public key",
  certificate: "Certificate", csr: "CSR"
};

export function ConvertView({ push }) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  async function run() {
    setErr(""); setResult(null);
    if (!input.trim()) { setErr("Paste a key, certificate or CSR first."); return; }
    setBusy(true);
    try {
      const r = await api.convertKey(input);
      setResult(r);
      push("Converted — " + (TYPE_LABEL[r.inputType] || r.inputType) + ", " + r.keyKind);
    } catch (e) { setErr(e.message || "Conversion failed."); }
    finally { setBusy(false); }
  }

  const copy = (v, label) => () => copyText(v).then(() => push(label + " copied"));

  return (
    <div className="stack fade-in" style={{ maxWidth: 860, margin: "0 auto" }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="refresh" /></span>
          <div>
            <h3>Key converter</h3>
            <div className="desc">Paste anything — a private key (PKCS#8, PKCS#1, SEC1), a public key, a certificate or a CSR — and get every format back. RSA, ECDSA, Ed25519 + post-quantum.</div>
          </div>
        </div>
        <div className="card-body fgroup">
          <Field label="Input" hint="Private keys are converted in memory and never stored. Encrypted keys aren't supported — decrypt first.">
            <textarea className="input mono" style={{ minHeight: 160 }} value={input}
              onChange={e => { setInput(e.target.value); setResult(null); setErr(""); }}
              placeholder={"-----BEGIN PRIVATE KEY-----   (or PUBLIC KEY / CERTIFICATE / CERTIFICATE REQUEST, or bare base64 DER)"}
              spellCheck={false} />
          </Field>
          <div><Button variant="primary" icon="refresh" loading={busy} onClick={run}>Convert</Button></div>
        </div>
      </div>

      {err && (
        <div className="card">
          <div className="card-body">
            <div className="warn-strip" style={{ background: "var(--danger-soft)", borderColor: "color-mix(in srgb, var(--danger) 30%, transparent)" }}>
              <Icon name="alert" style={{ color: "var(--danger)" }} />
              <span>{err}</span>
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className="card fade-in">
          <div className="card-body fgroup">
            <div className="warn-strip" style={{ background: "var(--success-soft)", borderColor: "color-mix(in srgb, var(--success) 32%, transparent)" }}>
              <Icon name="check" style={{ color: "var(--success)" }} />
              <span style={{ fontWeight: 600 }}>
                {TYPE_LABEL[result.inputType] || result.inputType} — {result.keyKind}
                {result.keyDetail && result.keyDetail !== result.keyKind ? " · " + result.keyDetail : ""}
                {" "}{result.pqc && <Pill kind="ok" icon="spark">post-quantum</Pill>}
              </span>
            </div>

            {(result.warnings || []).map((w, i) => (
              <div key={i} className="muted" style={{ fontSize: 13 }}><Icon name="info" style={{ width: 14, height: 14, verticalAlign: "-2px" }} /> {w}</div>
            ))}

            {result.pkcs8Pem && (
              <CodeBlock title="private key — PKCS#8" dots={false} value={result.pkcs8Pem}
                onCopy={copy(result.pkcs8Pem, "PKCS#8 key")} />
            )}
            {result.traditionalPem && (
              <CodeBlock title={"private key — traditional (" + (result.keyKind === "RSA" ? "PKCS#1" : "SEC1") + ")"}
                dots={false} value={result.traditionalPem}
                onCopy={copy(result.traditionalPem, "Traditional key")} />
            )}
            {result.publicPem && (
              <CodeBlock title="public key (SPKI)" dots={false} value={result.publicPem}
                onCopy={copy(result.publicPem, "Public key")} />
            )}
            {result.jwk && (
              <CodeBlock title="public JWK" dots={false} value={JSON.stringify(result.jwk, null, 2)}
                onCopy={copy(JSON.stringify(result.jwk, null, 2), "JWK")} />
            )}
            {result.sshPublicKey && (
              <CodeBlock title="OpenSSH public key" dots={false} value={result.sshPublicKey}
                onCopy={copy(result.sshPublicKey, "SSH key")} />
            )}

            <div className="kv">
              <dl>
                <dt>SPKI SHA-256</dt><dd className="mono" style={{ wordBreak: "break-all", fontSize: 12 }}>{result.spkiSha256 || "—"}</dd>
                <dt>SPKI pin (base64)</dt><dd className="mono" style={{ wordBreak: "break-all", fontSize: 12 }}>{result.spkiPin || "—"}</dd>
                {result.sshFingerprint && (<><dt>SSH fingerprint</dt><dd className="mono" style={{ wordBreak: "break-all", fontSize: 12 }}>{result.sshFingerprint}</dd></>)}
              </dl>
            </div>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {result.pkcs8DerBase64 && (
                <Button variant="soft" icon="download" onClick={() => downloadDer(result.pkcs8DerBase64, "private-key.der")}>Private key .der</Button>
              )}
              {result.publicDerBase64 && (
                <Button variant="soft" icon="download" onClick={() => downloadDer(result.publicDerBase64, "public-key.der")}>Public key .der</Button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
