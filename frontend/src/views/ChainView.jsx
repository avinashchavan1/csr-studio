/* Chain Builder — paste a messy certificate bundle (any order, junk between
   blocks is fine) and get the corrected leaf→root chain with per-link checks:
   signature, validity window, CA flags and key usage. Classical + PQC chains. */
import React, { useState } from "react";
import { Icon, Field, Button, Pill, CodeBlock } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import { copyText } from "../lib/data.js";

function CheckPill({ ok, okLabel, badLabel }) {
  return ok
    ? <Pill kind="ok" icon="check">{okLabel}</Pill>
    : <Pill kind="warn" icon="alert">{badLabel}</Pill>;
}

function CertCard({ cert, role, link }) {
  const bad = cert.expired || cert.notYetValid || (link && !(link.signatureValid && link.issuerIsCa && link.issuerCanSignCerts));
  return (
    <div className="card" style={{ borderColor: bad ? "color-mix(in srgb, var(--danger) 40%, transparent)" : undefined }}>
      <div className="card-body fgroup" style={{ gap: 10 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Pill kind={role === "Leaf" ? "ok" : "neutral"} icon={role === "Root" ? "shield" : role === "Leaf" ? "cert" : "layers"}>{role}</Pill>
          <span style={{ fontWeight: 600, wordBreak: "break-all" }}>{cert.subject}</span>
          {cert.pqc && <Pill kind="ok" icon="spark">post-quantum</Pill>}
        </div>
        <div className="kv">
          <dl>
            <dt>Issuer</dt><dd style={{ wordBreak: "break-all" }}>{cert.issuer}</dd>
            <dt>Key</dt><dd>{cert.keyKind}{cert.keyDetail && cert.keyDetail !== cert.keyKind ? " · " + cert.keyDetail : ""}</dd>
            <dt>Signature</dt><dd>{cert.signatureAlgorithm}</dd>
            <dt>Validity</dt>
            <dd>{cert.notBefore} → {cert.notAfter}{" "}
              {cert.expired ? <Pill kind="warn" icon="alert">expired</Pill>
                : cert.notYetValid ? <Pill kind="warn" icon="alert">not yet valid</Pill>
                : <Pill kind="ok" icon="check">in window</Pill>}
            </dd>
            <dt>CA</dt><dd>{cert.ca ? "yes" + (cert.pathLen != null ? " (pathlen " + cert.pathLen + ")" : "") : "no"}{cert.selfSigned ? " · self-signed" : ""}</dd>
            <dt>Serial</dt><dd className="mono" style={{ wordBreak: "break-all", fontSize: 12 }}>{cert.serialHex}</dd>
          </dl>
        </div>
      </div>
    </div>
  );
}

export function ChainView({ push }) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  async function run() {
    setErr(""); setResult(null);
    if (!input.trim()) { setErr("Paste one or more PEM certificates first."); return; }
    setBusy(true);
    try {
      const r = await api.chain(input);
      setResult(r);
      push(r.allValid ? "Chain is complete and valid" : "Chain analysed — see the findings");
    } catch (e) { setErr(e.message || "Chain analysis failed."); }
    finally { setBusy(false); }
  }

  const roleOf = (i, n, cert) =>
    cert.selfSigned && i === n - 1 ? "Root" : i === 0 ? "Leaf" : "Intermediate";

  return (
    <div className="stack fade-in" style={{ maxWidth: 860, margin: "0 auto" }}>
      <div className="card">
        <div className="card-head">
          <span className="ico"><Icon name="link" /></span>
          <div>
            <h3>Chain builder &amp; validator</h3>
            <div className="desc">Paste your certificate bundle in any order — leaf, intermediates, root, even with junk text between blocks. Get the corrected order and every link checked.</div>
          </div>
        </div>
        <div className="card-body fgroup">
          <Field label="Certificate bundle" hint="Only certificates — never paste private keys here.">
            <textarea className="input mono" style={{ minHeight: 180 }} value={input}
              onChange={e => { setInput(e.target.value); setResult(null); setErr(""); }}
              placeholder={"-----BEGIN CERTIFICATE-----\n(leaf, intermediates and root — any order)\n-----END CERTIFICATE-----"}
              spellCheck={false} />
          </Field>
          <div><Button variant="primary" icon="link" loading={busy} onClick={run}>Build &amp; validate chain</Button></div>
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
        <>
          <div className="card fade-in">
            <div className="card-body fgroup">
              <div className="warn-strip" style={{
                background: result.allValid ? "var(--success-soft)" : "var(--danger-soft)",
                borderColor: result.allValid ? "color-mix(in srgb, var(--success) 32%, transparent)" : "color-mix(in srgb, var(--danger) 32%, transparent)"
              }}>
                <Icon name={result.allValid ? "check" : "alert"} style={{ color: result.allValid ? "var(--success)" : "var(--danger)" }} />
                <span style={{ fontWeight: 600 }}>
                  {result.allValid
                    ? "Chain complete and valid — " + result.chain.length + " certificate" + (result.chain.length > 1 ? "s" : "") + ", every link checks out."
                    : result.complete
                      ? "Chain is complete but has problems — see the checks below."
                      : "Chain is incomplete — missing an issuer."}
                </span>
              </div>
              {!result.complete && result.missingIssuer && (
                <div className="muted" style={{ fontSize: 13 }}>
                  Missing issuer: <b style={{ wordBreak: "break-all" }}>{result.missingIssuer}</b>
                  {result.missingIssuerUrl && <> — its certificate may be downloadable at{" "}
                    <span className="mono" style={{ wordBreak: "break-all" }}>{result.missingIssuerUrl}</span></>}
                </div>
              )}
              {(result.warnings || []).map((w, i) => (
                <div key={i} className="muted" style={{ fontSize: 13 }}>
                  <Icon name="info" style={{ width: 14, height: 14, verticalAlign: "-2px" }} /> {w}
                </div>
              ))}
            </div>
          </div>

          <div className="stack" style={{ gap: 0 }}>
            {result.chain.map((cert, i) => {
              const link = (result.links || []).find(l => l.childIndex === i);
              return (
                <React.Fragment key={i}>
                  <CertCard cert={cert} role={roleOf(i, result.chain.length, cert)} link={link} />
                  {link && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 6px 10px 22px", flexWrap: "wrap" }}>
                      <Icon name="arrow" style={{ width: 15, height: 15, transform: "rotate(90deg)", color: "var(--muted)" }} />
                      <span className="muted" style={{ fontSize: 12 }}>signed by ↓</span>
                      <CheckPill ok={link.signatureValid} okLabel="signature" badLabel="signature fails" />
                      <CheckPill ok={link.issuerIsCa} okLabel="issuer is CA" badLabel="issuer not a CA" />
                      <CheckPill ok={link.issuerCanSignCerts} okLabel="keyCertSign" badLabel="no keyCertSign" />
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>

          {result.extras && result.extras.length > 0 && (
            <div className="card">
              <div className="card-body fgroup">
                <div style={{ fontWeight: 600, fontSize: 14 }}>Not part of this chain</div>
                {result.extras.map((c, i) => (
                  <div key={i} className="muted" style={{ fontSize: 13, wordBreak: "break-all" }}>
                    <Icon name="x" style={{ width: 13, height: 13, verticalAlign: "-2px", color: "var(--danger)" }} /> {c.subject}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.orderedPem && (
            <CodeBlock title="corrected chain (leaf → root)" dots={false} value={result.orderedPem}
              onCopy={() => copyText(result.orderedPem).then(() => push("Corrected chain copied"))} />
          )}
        </>
      )}
    </div>
  );
}
