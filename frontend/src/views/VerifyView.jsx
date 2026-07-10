/* Verify a digital signature — detached (message + signature + public key/cert)
   or certificate-signed-by-issuer. Classical + post-quantum. Backend-only. */
import React, { useState } from "react";
import { Icon, Field, TextInput, Segmented, Button, Pill, Switch } from "../components/ui.jsx";
import * as api from "../lib/api.js";

const MAX_FILE = 5 * 1024 * 1024; // 5 MB

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function VerifyView({ push }) {
  const [mode, setMode] = useState("detached");

  // detached
  const [inputType, setInputType] = useState("text");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState(null);       // { name, b64 }
  const [bytes, setBytes] = useState("");
  const [bytesEnc, setBytesEnc] = useState("base64");
  const [signature, setSignature] = useState("");
  const [sigEnc, setSigEnc] = useState("base64");
  const [verifier, setVerifier] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [hash, setHash] = useState("SHA-256");
  const [rsaPss, setRsaPss] = useState(false);

  // issuer
  const [leaf, setLeaf] = useState("");
  const [issuer, setIssuer] = useState("");

  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  function reset() { setResult(null); setErr(""); }

  async function onFile(e) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > MAX_FILE) { push("File is larger than 5 MB.", "err"); return; }
    const buf = await f.arrayBuffer();
    setFile({ name: f.name, b64: arrayBufferToBase64(buf) });
    reset();
  }

  async function verifyDetached() {
    reset();
    if (!verifier.trim()) { setErr("Paste the public key or certificate to verify against."); return; }
    if (!signature.trim()) { setErr("Paste the signature to verify."); return; }
    let msg, msgEnc;
    if (inputType === "text") { msg = message; msgEnc = "utf8"; }
    else if (inputType === "file") {
      if (!file) { setErr("Choose a file to verify."); return; }
      msg = file.b64; msgEnc = "base64";
    } else { msg = bytes; msgEnc = bytesEnc; }

    setBusy(true);
    try {
      const res = await api.verify({
        mode: "detached",
        message: msg, messageEncoding: msgEnc,
        signature, signatureEncoding: sigEnc,
        publicKey: verifier,
        algorithm: "auto", hash, rsaPss
      });
      setResult(res);
    } catch (e) { setErr(e.message || "Verification failed."); }
    finally { setBusy(false); }
  }

  async function verifyIssuer() {
    reset();
    if (!leaf.trim()) { setErr("Paste the certificate to check."); return; }
    if (!issuer.trim()) { setErr("Paste the issuer (CA) certificate."); return; }
    setBusy(true);
    try {
      const res = await api.verify({ mode: "issuer", certificate: leaf, issuerCertificate: issuer });
      setResult(res);
    } catch (e) { setErr(e.message || "Verification failed."); }
    finally { setBusy(false); }
  }

  const fmtDate = (ms) => ms ? new Date(ms).toISOString().slice(0, 10) : "—";

  return (
    <div className="stack fade-in" style={{ maxWidth: 860, margin: "0 auto" }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="check" /></span>
          <div>
            <h3>Verify a signature</h3>
            <div className="desc">Confirm a signature is authentic — classical (RSA, ECDSA, Ed25519) and post-quantum (ML-DSA, SLH-DSA, Falcon). Public-key only; nothing is stored.</div>
          </div>
        </div>
        <div className="card-body fgroup">
          <Field label="What do you want to verify?">
            <Segmented value={mode} onChange={v => { setMode(v); reset(); }}
              options={[{ value: "detached", label: "Detached signature" }, { value: "issuer", label: "Certificate & issuer" }]} />
          </Field>
        </div>
      </div>

      {mode === "detached" && (
        <div className="card">
          <div className="card-body fgroup">
            <Field label="Signed input" hint="What was signed — paste text, upload the file, or paste the raw bytes.">
              <Segmented value={inputType} onChange={v => { setInputType(v); reset(); }}
                options={[{ value: "text", label: "Text" }, { value: "file", label: "File" }, { value: "bytes", label: "Hex / Base64" }]} />
            </Field>

            {inputType === "text" && (
              <textarea className="input mono" style={{ minHeight: 90 }} value={message}
                onChange={e => { setMessage(e.target.value); reset(); }} placeholder="The exact text that was signed" spellCheck={false} />
            )}
            {inputType === "file" && (
              <div className="input-row" style={{ alignItems: "center" }}>
                <input type="file" onChange={onFile} />
                {file && <Pill kind="ok" icon="check">{file.name}</Pill>}
              </div>
            )}
            {inputType === "bytes" && (
              <>
                <textarea className="input mono" style={{ minHeight: 70 }} value={bytes}
                  onChange={e => { setBytes(e.target.value); reset(); }} placeholder="Raw signed bytes" spellCheck={false} />
                <Field label="Bytes encoding">
                  <Segmented value={bytesEnc} onChange={setBytesEnc}
                    options={[{ value: "base64", label: "Base64" }, { value: "hex", label: "Hex" }]} />
                </Field>
              </>
            )}

            <Field label="Signature">
              <textarea className="input mono" style={{ minHeight: 70 }} value={signature}
                onChange={e => { setSignature(e.target.value); reset(); }} placeholder="The signature to verify" spellCheck={false} />
            </Field>
            <Field label="Signature encoding">
              <Segmented value={sigEnc} onChange={setSigEnc}
                options={[{ value: "base64", label: "Base64" }, { value: "hex", label: "Hex" }]} />
            </Field>

            <Field label="Public key or certificate" hint="The verifier — a PEM public key, or a certificate whose key will be used.">
              <textarea className="input mono" style={{ minHeight: 120 }} value={verifier}
                onChange={e => { setVerifier(e.target.value); reset(); }}
                placeholder="-----BEGIN PUBLIC KEY-----  (or a certificate)" spellCheck={false} />
            </Field>

            <button className="link-btn" style={{ alignSelf: "flex-start", background: "none", border: 0, color: "var(--accent)", cursor: "pointer", fontSize: 13, padding: 0 }}
              onClick={() => setShowAdvanced(s => !s)}>
              {showAdvanced ? "Hide" : "Show"} advanced (hash / RSA-PSS)
            </button>
            {showAdvanced && (
              <div className="frow">
                <Field label="Hash (RSA / ECDSA)" hint="Ignored for Ed25519 and PQC.">
                  <Segmented value={hash} onChange={setHash}
                    options={[{ value: "SHA-256", label: "SHA-256" }, { value: "SHA-384", label: "SHA-384" }, { value: "SHA-512", label: "SHA-512" }]} />
                </Field>
                <Field label="RSA padding">
                  <Switch value={rsaPss} onChange={setRsaPss} label="Use RSA-PSS (instead of PKCS#1 v1.5)" />
                </Field>
              </div>
            )}

            <div>
              <Button variant="primary" icon="check" loading={busy} onClick={verifyDetached}>Verify signature</Button>
            </div>
          </div>
        </div>
      )}

      {mode === "issuer" && (
        <div className="card">
          <div className="card-body fgroup">
            <Field label="Certificate to check" hint="The leaf / end-entity certificate.">
              <textarea className="input mono" style={{ minHeight: 130 }} value={leaf}
                onChange={e => { setLeaf(e.target.value); reset(); }} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} />
            </Field>
            <Field label="Issuer (CA) certificate" hint="The certificate that supposedly signed it.">
              <textarea className="input mono" style={{ minHeight: 130 }} value={issuer}
                onChange={e => { setIssuer(e.target.value); reset(); }} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} />
            </Field>
            <div>
              <Button variant="primary" icon="check" loading={busy} onClick={verifyIssuer}>Verify certificate</Button>
            </div>
          </div>
        </div>
      )}

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
            <div className="warn-strip" style={{
              background: result.valid ? "var(--success-soft)" : "var(--danger-soft)",
              borderColor: result.valid ? "color-mix(in srgb, var(--success) 32%, transparent)" : "color-mix(in srgb, var(--danger) 32%, transparent)"
            }}>
              <Icon name={result.valid ? "check" : "alert"} style={{ color: result.valid ? "var(--success)" : "var(--danger)" }} />
              <span style={{ fontWeight: 600 }}>
                {result.valid
                  ? (mode === "issuer" ? "Signature valid — this certificate was signed by that issuer." : "Signature valid — it matches the message and key.")
                  : "Not valid."}
              </span>
            </div>
            {result.reason && <div className="muted" style={{ fontSize: 13 }}>{result.reason}</div>}

            <div className="kv">
              <dl>
                <dt>Algorithm</dt><dd>{result.algorithm || "—"}</dd>
                <dt>Key type</dt><dd>{result.keyKind || "—"} {result.pqc && <Pill kind="ok" icon="spark">post-quantum</Pill>}</dd>
                {mode === "issuer" && (
                  <>
                    <dt>Subject</dt><dd style={{ wordBreak: "break-all" }}>{result.subject || "—"}</dd>
                    <dt>Issuer</dt><dd style={{ wordBreak: "break-all" }}>{result.issuer || "—"}</dd>
                    <dt>Valid dates</dt><dd>{fmtDate(result.notBefore)} → {fmtDate(result.notAfter)} {result.timeValid ? <Pill kind="ok" icon="check">in window</Pill> : <Pill kind="warn" icon="alert">out of window</Pill>}</dd>
                    <dt>Issuer name match</dt><dd>{result.nameChainOk ? <Pill kind="ok" icon="check">matches</Pill> : <Pill kind="warn" icon="alert">mismatch</Pill>}</dd>
                  </>
                )}
              </dl>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
