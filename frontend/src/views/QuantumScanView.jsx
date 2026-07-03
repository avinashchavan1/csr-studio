/* Quantum-readiness scanner — grade a live domain, CSR, or certificate. */
import React, { useState, useEffect } from "react";
import { Icon, Field, TextInput, Segmented, Button, Pill } from "../components/ui.jsx";
import * as api from "../lib/api.js";
import { copyText } from "../lib/data.js";

const GRADE_COLOR = (g) => g && g.startsWith("A") ? "var(--success)" : g === "F" ? "var(--danger)" : "var(--warning)";

export function QuantumScanView({ push, onGenerateHybrid, seedHost }) {
  const [kind, setKind] = useState("host");
  const [host, setHost] = useState("");
  const [pem, setPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [scannedHost, setScannedHost] = useState(null);
  const [err, setErr] = useState("");

  // deep-link: /?scan=<domain> auto-runs a host scan
  useEffect(() => {
    if (seedHost) { setKind("host"); setHost(seedHost); scan({ host: seedHost }); }
    // eslint-disable-next-line
  }, [seedHost]);

  async function scan(override) {
    setErr(""); setReport(null);
    const payload = override || (kind === "host"
      ? { host: host.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "") }
      : kind === "csr" ? { csr: pem.trim() } : { certificate: pem.trim() });
    const val = payload.host || payload.csr || payload.certificate || "";
    if (!val) { setErr(kind === "host" ? "Enter a domain, e.g. example.com" : "Paste a PEM block first."); return; }
    setBusy(true);
    try {
      const r = await api.quantumScan(payload);
      setReport(r);
      setScannedHost(payload.host || null);
      // reflect a host scan in the URL so it's shareable
      if (payload.host) {
        try { history.replaceState(null, "", "/quantum?scan=" + encodeURIComponent(payload.host)); } catch (e) {}
      }
      push("Scanned " + (r.target || val));
    } catch (e) {
      setErr(e.message || "Scan failed");
    } finally { setBusy(false); }
  }

  function shareReport() {
    if (!report) return;
    const link = location.origin + "/?scan=" + encodeURIComponent(scannedHost);
    copyText(link).then(() => push("Shareable scan link copied")).catch(() => push("Copy failed", "err"));
  }

  return (
    <div className="grid-2 fade-in">
      <div className="stack">
        <div className="card">
          <div className="card-head">
            <span className="ico"><Icon name="spark" /></span>
            <div><h3>Quantum-readiness scan</h3><div className="desc">Is this key breakable by a quantum computer? Grade a live site, CSR, or certificate.</div></div>
          </div>
          <div className="card-body fgroup">
            <Field label="What to scan">
              <Segmented value={kind} onChange={v => { setKind(v); setReport(null); setErr(""); }}
                options={[{ value: "host", label: "Live domain" }, { value: "csr", label: "CSR" }, { value: "certificate", label: "Certificate" }]} />
            </Field>
            {kind === "host" ? (
              <Field label="Domain" hint="We fetch the site's live TLS certificate and grade its cryptography. Nothing is stored." error={err}>
                <TextInput mono value={host} onChange={setHost} placeholder="example.com"
                  onKeyDown={e => { if (e.key === "Enter") scan(); }} />
              </Field>
            ) : (
              <Field label={kind === "csr" ? "PEM CSR" : "PEM certificate"} error={err}>
                <textarea className={"input mono" + (err ? " err" : "")} value={pem} onChange={e => setPem(e.target.value)}
                  placeholder={kind === "csr" ? "-----BEGIN CERTIFICATE REQUEST-----" : "-----BEGIN CERTIFICATE-----"}
                  style={{ minHeight: 180 }} spellCheck={false} />
              </Field>
            )}
            <div style={{ display: "flex", gap: 10 }}>
              <Button variant="primary" icon="spark" loading={busy} onClick={() => scan()}>Scan quantum readiness</Button>
              {(host || pem) && <Button variant="ghost" icon="x" onClick={() => { setHost(""); setPem(""); setReport(null); setErr(""); }}>Clear</Button>}
            </div>
            <div className="warn-strip" style={{ background: "var(--surface-3)", borderColor: "var(--border)" }}>
              <Icon name="info" style={{ color: "var(--accent)" }} />
              <span><b>Why this matters:</b> traffic recorded today under RSA/ECDSA can be decrypted later by a quantum computer (“harvest now, decrypt later”). NIST's ML-DSA / SLH-DSA are quantum-resistant.</span>
            </div>
          </div>
        </div>
      </div>

      <div className="stack" style={{ position: "sticky", top: 92 }}>
        {!report && !busy && (
          <div className="result-empty">
            <span className="big"><Icon name="spark" /></span>
            <h4>Your quantum report appears here</h4>
            <p>Scan any public site (try your own domain) — or paste a CSR / certificate — and get an HNDL risk grade with a migration plan.</p>
          </div>
        )}
        {busy && (
          <div className="result-empty">
            <span className="big"><span className="spinner" style={{ width: 26, height: 26, borderColor: "var(--accent-ring)", borderTopColor: "var(--accent)" }} /></span>
            <h4>Scanning…</h4>
            <p>{kind === "host" ? "Fetching the live TLS certificate and grading its cryptography." : "Grading the key and signature algorithms."}</p>
          </div>
        )}
        {report && (
          <div className="stack fade-in">
            <div className="card" style={{ borderColor: "color-mix(in srgb, " + GRADE_COLOR(report.grade) + " 40%, transparent)" }}>
              <div className="card-body" style={{ display: "flex", alignItems: "center", gap: 18 }}>
                <div style={{
                  width: 74, height: 74, borderRadius: 16, display: "grid", placeItems: "center", flex: "none",
                  background: "color-mix(in srgb, " + GRADE_COLOR(report.grade) + " 14%, transparent)",
                  color: GRADE_COLOR(report.grade), fontFamily: "var(--font-head)", fontWeight: 700, fontSize: 34
                }}>{report.grade}</div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontWeight: 600, fontSize: 15, overflow: "hidden", textOverflow: "ellipsis" }}>{report.target}</div>
                  <div className="muted" style={{ fontSize: 13, marginTop: 3 }}>
                    {report.keyAlgorithm} {report.keyDetail} · {report.signatureAlgorithm || "—"}
                  </div>
                  <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Pill kind={report.quantumVulnerable ? "warn" : "ok"} icon={report.quantumVulnerable ? "alert" : "check"}>
                      {report.quantumVulnerable ? "Quantum-vulnerable" : "Quantum-safe"}
                    </Pill>
                    <Pill kind={report.hndlRisk === "none" ? "ok" : report.hndlRisk === "high" ? "warn" : "info"}>HNDL risk: {report.hndlRisk}</Pill>
                    <Pill kind="neutral">exposure {report.score}/100</Pill>
                  </div>
                </div>
                {scannedHost && (
                  <Button variant="ghost" size="sm" icon="arrow" onClick={shareReport} title="Copy a shareable link to this scan">Share</Button>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="search" /></span><h3>Findings</h3></div>
              <div className="card-body">
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {report.findings.map((x, i) => <li key={i} style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 6 }}>{x}</li>)}
                </ul>
              </div>
            </div>

            <div className="card">
              <div className="card-head"><span className="ico"><Icon name="arrow" /></span><h3>Recommendation</h3></div>
              <div className="card-body stack">
                <span style={{ fontSize: 13.5 }}>{report.recommendation}</span>
                {report.quantumVulnerable && (
                  <Button variant="primary" icon="spark" onClick={() => onGenerateHybrid && onGenerateHybrid(report.target)}>
                    Generate a hybrid (classical + ML-DSA) CSR now
                  </Button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
