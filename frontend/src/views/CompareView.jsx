/* Compare two CSRs side by side — subject, SANs, key, signature, extensions. */
import React, { useState } from "react";
import { Icon, Button, Pill } from "../components/ui.jsx";
import * as api from "../lib/api.js";

const FIELDS = [
  ["CN", "Common Name"], ["O", "Organization"], ["OU", "Org. Unit"],
  ["L", "Locality"], ["ST", "State"], ["C", "Country"], ["email", "Email"]
];

function sansText(d) {
  return (d.sans || []).map(s => s.type + ":" + s.value).sort().join(", ") || "—";
}
function extText(d) {
  const e = d.extensions;
  if (!e) return "—";
  const parts = [];
  if (e.keyUsage) parts.push("KU: " + e.keyUsage.join("/"));
  if (e.extendedKeyUsage) parts.push("EKU: " + e.extendedKeyUsage.join("/"));
  if (e.basicConstraints) parts.push(e.basicConstraints);
  return parts.join(" · ") || "—";
}

export function CompareView({ push }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [da, setDa] = useState(null);
  const [db, setDb] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function compare() {
    setErr(""); setDa(null); setDb(null);
    if (!a.trim() || !b.trim()) { setErr("Paste a CSR on both sides."); return; }
    setBusy(true);
    try {
      const [ra, rb] = await Promise.all([api.decode(a.trim()), api.decode(b.trim())]);
      setDa(ra); setDb(rb);
      push("CSRs compared");
    } catch (e) {
      setErr(e.message || "Couldn't decode one of the CSRs.");
    } finally { setBusy(false); }
  }

  const rows = da && db ? [
    ...FIELDS.map(([k, lbl]) => [lbl, da.subject[k] || "—", db.subject[k] || "—"]),
    ["SANs", sansText(da), sansText(db)],
    ["Key", (da.keyKind + " " + (da.keyDetail || "")).trim(), (db.keyKind + " " + (db.keyDetail || "")).trim()],
    ["Signature", da.sigAlg || "—", db.sigAlg || "—"],
    ["Sig valid", String(da.verified), String(db.verified)],
    ["Extensions", extText(da), extText(db)],
    ["Key SHA-256", da.keySha256 || "—", db.keySha256 || "—"]
  ] : [];
  const diffs = rows.filter(r => r[1] !== r[2]).length;

  return (
    <div className="fade-in stack">
      <div className="frow" style={{ alignItems: "start" }}>
        {[["A", a, setA], ["B", b, setB]].map(([lbl, val, set]) => (
          <div className="card" key={lbl}>
            <div className="card-head"><span className="ico"><Icon name="file" /></span><h3>CSR {lbl}</h3></div>
            <div className="card-body">
              <textarea className="input mono" value={val} onChange={e => set(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE REQUEST-----" style={{ minHeight: 170 }} spellCheck={false} />
            </div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <Button variant="primary" icon="layers" loading={busy} onClick={compare}>Compare</Button>
        {(a || b) && <Button variant="ghost" icon="x" onClick={() => { setA(""); setB(""); setDa(null); setDb(null); setErr(""); }}>Clear</Button>}
        {err && <span className="field-err"><Icon name="alert" />{err}</span>}
        {da && db && (
          diffs === 0
            ? <Pill kind="ok" icon="check">Identical fields</Pill>
            : <Pill kind="warn" icon="alert">{diffs} difference{diffs === 1 ? "" : "s"}</Pill>
        )}
      </div>

      {da && db && (
        <div className="card fade-in">
          <div className="card-head"><span className="ico"><Icon name="layers" /></span><h3>Field-by-field</h3></div>
          <div className="card-body" style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-muted)" }}>
                  <th style={{ padding: "6px 10px" }}>Field</th>
                  <th style={{ padding: "6px 10px" }}>CSR A</th>
                  <th style={{ padding: "6px 10px" }}>CSR B</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(([lbl, va, vb], i) => {
                  const diff = va !== vb;
                  return (
                    <tr key={i} style={{
                      borderTop: "1px solid var(--border)",
                      background: diff ? "var(--warning-soft)" : "transparent"
                    }}>
                      <td style={{ padding: "7px 10px", fontWeight: 600, whiteSpace: "nowrap" }}>
                        {diff && <Icon name="alert" style={{ width: 12, height: 12, color: "var(--warning)", marginRight: 6, verticalAlign: "-1px" }} />}{lbl}
                      </td>
                      <td className="mono" style={{ padding: "7px 10px", wordBreak: "break-all", fontSize: 12 }}>{va}</td>
                      <td className="mono" style={{ padding: "7px 10px", wordBreak: "break-all", fontSize: 12 }}>{vb}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
