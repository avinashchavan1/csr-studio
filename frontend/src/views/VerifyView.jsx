/* Sign & Verify — sign a message with a private key (server-side, key never stored),
   verify a detached signature, or verify a certificate against its issuer.
   Classical + post-quantum. Sign output pre-fills Verify for a one-click round-trip. */
import React, { useState } from "react";
import { Icon, Field, Segmented, Button, Pill, Switch, CodeBlock } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import { copyText } from "../lib/data.js";

const MAX_FILE = 5 * 1024 * 1024; // 5 MB

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function VerifyView({ push }) {
  const [mode, setMode] = useState("sign");

  // shared "signed input"
  const [inputType, setInputType] = useState("text");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState(null);
  const [bytes, setBytes] = useState("");
  const [bytesEnc, setBytesEnc] = useState("base64");

  // verify (detached)
  const [signature, setSignature] = useState("");
  const [sigEnc, setSigEnc] = useState("base64");
  const [verifier, setVerifier] = useState("");

  // sign
  const [privateKey, setPrivateKey] = useState("");
  const [signResult, setSignResult] = useState(null);

  // advanced (shared by sign + detached verify)
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
  function resetAll() { reset(); setSignResult(null); }

  async function onFile(e) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > MAX_FILE) { push("File is larger than 5 MB.", "err"); return; }
    const buf = await f.arrayBuffer();
    setFile({ name: f.name, b64: arrayBufferToBase64(buf) });
    resetAll();
  }

  // Resolve the shared signed input into { msg, msgEnc }, or null with an error set.
  function messagePayload() {
    if (inputType === "text") return { msg: message, msgEnc: "utf8" };
    if (inputType === "file") {
      if (!file) { setErr("Choose a file first."); return null; }
      return { msg: file.b64, msgEnc: "base64" };
    }
    return { msg: bytes, msgEnc: bytesEnc };
  }

  async function doSign() {
    reset(); setSignResult(null);
    if (!privateKey.trim()) { setErr("Paste the private key to sign with."); return; }
    const mp = messagePayload(); if (!mp) return;
    setBusy(true);
    try {
      const res = await api.sign({
        message: mp.msg, messageEncoding: mp.msgEnc,
        privateKey, algorithm: "auto", hash, rsaPss
      });
      setSignResult(res);
      push("Signed with " + res.algorithm);
    } catch (e) { setErr(e.message || "Signing failed."); }
    finally { setBusy(false); }
  }

  // Take the sign result and run a verify with it (the round-trip).
  async function verifySigned() {
    if (!signResult) return;
    setSignature(signResult.signature); setSigEnc("base64"); setVerifier(signResult.publicKey || "");
    setMode("detached");
    await runVerify({ sig: signResult.signature, se: "base64", pub: signResult.publicKey });
  }

  async function runVerify(override) {
    reset();
    const sig = override ? override.sig : signature;
    const se = override ? override.se : sigEnc;
    const pub = override ? override.pub : verifier;
    if (!pub || !pub.trim()) { setErr("Paste the public key or certificate to verify against."); return; }
    if (!sig || !sig.trim()) { setErr("Paste the signature to verify."); return; }
    const mp = messagePayload(); if (!mp) return;
    setBusy(true);
    try {
      const res = await api.verify({
        mode: "detached",
        message: mp.msg, messageEncoding: mp.msgEnc,
        signature: sig, signatureEncoding: se,
        publicKey: pub, algorithm: "auto", hash, rsaPss
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

  function renderSignedInput() {
    return (
      <>
        <Field label="Signed input" hint="What was (or will be) signed — text, a file, or raw bytes.">
          <Segmented value={inputType} onChange={v => { setInputType(v); resetAll(); }}
            options={[{ value: "text", label: "Text" }, { value: "file", label: "File" }, { value: "bytes", label: "Hex / Base64" }]} />
        </Field>
        {inputType === "text" && (
          <textarea className="input mono" style={{ minHeight: 90 }} value={message}
            onChange={e => { setMessage(e.target.value); resetAll(); }} placeholder="The exact text to sign / that was signed" spellCheck={false} />
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
              onChange={e => { setBytes(e.target.value); resetAll(); }} placeholder="Raw bytes" spellCheck={false} />
            <Field label="Bytes encoding">
              <Segmented value={bytesEnc} onChange={setBytesEnc}
                options={[{ value: "base64", label: "Base64" }, { value: "hex", label: "Hex" }]} />
            </Field>
          </>
        )}
      </>
    );
  }

  function renderAdvanced() {
    return (
      <>
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
      </>
    );
  }

  return (
    <div className="stack fade-in" style={{ maxWidth: 860, margin: "0 auto" }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="check" /></span>
          <div>
            <h3>Sign &amp; verify</h3>
            <div className="desc">Sign a message with a private key, or verify a signature — classical (RSA, ECDSA, Ed25519) and post-quantum (ML-DSA, SLH-DSA, Falcon).</div>
          </div>
        </div>
        <div className="card-body fgroup">
          <Field label="What do you want to do?">
            <Segmented value={mode} onChange={v => { setMode(v); reset(); }}
              options={[{ value: "sign", label: "Sign" }, { value: "detached", label: "Verify" }, { value: "issuer", label: "Cert & issuer" }]} />
          </Field>
        </div>
      </div>

      {mode === "sign" && (
        <div className="card">
          <div className="card-body fgroup">
            {renderSignedInput()}
            <Field label="Private key" hint="Used only to produce the signature — sent over TLS, never stored.">
              <textarea className="input mono" style={{ minHeight: 120 }} value={privateKey}
                onChange={e => { setPrivateKey(e.target.value); resetAll(); }}
                placeholder="-----BEGIN PRIVATE KEY-----" spellCheck={false} />
            </Field>
            {renderAdvanced()}
            <div><Button variant="primary" icon="key" loading={busy} onClick={doSign}>Sign message</Button></div>
          </div>
        </div>
      )}

      {mode === "sign" && signResult && (
        <div className="card fade-in">
          <div className="card-body fgroup">
            <div className="warn-strip" style={{ background: "var(--success-soft)", borderColor: "color-mix(in srgb, var(--success) 32%, transparent)" }}>
              <Icon name="check" style={{ color: "var(--success)" }} />
              <span style={{ fontWeight: 600 }}>Signed with {signResult.algorithm} {signResult.pqc && <Pill kind="ok" icon="spark">post-quantum</Pill>}</span>
            </div>
            <CodeBlock title="signature (base64)" dots={false} value={signResult.signature}
              onCopy={() => copyText(signResult.signature).then(() => push("Signature copied"))} />
            <CodeBlock title="signature (hex)" dots={false} value={signResult.signatureHex}
              onCopy={() => copyText(signResult.signatureHex).then(() => push("Signature (hex) copied"))} />
            {signResult.publicKey && (
              <CodeBlock title="public key (to verify with)" dots={false} value={signResult.publicKey}
                onCopy={() => copyText(signResult.publicKey).then(() => push("Public key copied"))} />
            )}
            <div><Button variant="soft" icon="arrow" loading={busy} onClick={verifySigned}>Verify this signature →</Button></div>
          </div>
        </div>
      )}

      {mode === "detached" && (
        <div className="card">
          <div className="card-body fgroup">
            {renderSignedInput()}
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
            {renderAdvanced()}
            <div><Button variant="primary" icon="check" loading={busy} onClick={() => runVerify(null)}>Verify signature</Button></div>
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
            <div><Button variant="primary" icon="check" loading={busy} onClick={verifyIssuer}>Verify certificate</Button></div>
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
                  ? (result.mode === "issuer" ? "Signature valid — this certificate was signed by that issuer." : "Signature valid — it matches the message and key.")
                  : "Not valid."}
              </span>
            </div>
            {result.reason && <div className="muted" style={{ fontSize: 13 }}>{result.reason}</div>}
            <div className="kv">
              <dl>
                <dt>Algorithm</dt><dd>{result.algorithm || "—"}</dd>
                <dt>Key type</dt><dd>{result.keyKind || "—"} {result.pqc && <Pill kind="ok" icon="spark">post-quantum</Pill>}</dd>
                {result.mode === "issuer" && (
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
