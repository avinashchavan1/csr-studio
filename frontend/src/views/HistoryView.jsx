/* Locally-stored CSR history (ported from design views-history.jsx) */
import React, { useState } from "react";
import { Icon, Button, CodeBlock } from "../components/ui.jsx";
import { copyText, download, safeName, timeAgo, fullDate } from "../lib/data.js";
import * as api from "../lib/api.js";

export function HistoryView({ items, onDelete, onClear, onRegenerate, push }) {
  const [open, setOpen] = useState(null);
  const connected = api.mode() === "connected";

  if (!items.length) {
    return (
      <div className="fade-in">
        <div className="result-empty" style={{ maxWidth: 560, margin: "40px auto" }}>
          <span className="big"><Icon name="history" /></span>
          <h4>No saved requests yet</h4>
          <p>{connected
            ? `Every CSR you generate is saved on ${api.host()} (the request + metadata only — never the private key) so you can revisit it from anywhere.`
            : "Every CSR you generate is saved here in this browser so you can re-download or revisit it. Nothing is uploaded anywhere."}</p>
        </div>
      </div>
    );
  }

  const doCopy = (t, w) => copyText(t).then(() => push(w + " copied")).catch(() => push("Copy failed", "err"));

  return (
    <div className="fade-in">
      <div style={{ display: "flex", alignItems: "center", marginBottom: 18 }}>
        <div className="muted" style={{ fontSize: 13 }}>
          <Icon name="lock" style={{ width: 13, height: 13, verticalAlign: "-2px", marginRight: 6 }} />
          {items.length} request{items.length > 1 ? "s" : ""} {connected
            ? `stored on ${api.host()} — CSR + metadata only, never the private key.`
            : "stored locally in this browser only."}
        </div>
        <div style={{ marginLeft: "auto" }}>
          <Button variant="ghost" size="sm" icon="trash" onClick={() => { if (confirm("Delete all saved requests? This can't be undone.")) { onClear(); setOpen(null); push("History cleared"); } }}>Clear all</Button>
        </div>
      </div>

      <div className="hist-list">
        {items.map((it, i) => (
          <React.Fragment key={it.id}>
            <div className="hist-item" onClick={() => setOpen(open === i ? null : i)}>
              <span className="hist-ico"><Icon name="cert" /></span>
              <div className="hist-main">
                <div className="hist-cn">{it.subject.CN || "(no common name)"}</div>
                <div className="hist-meta">
                  <span>{it.keyLabel}</span>
                  <span>{it.sigAlg}</span>
                  <span>{it.sans.length} SAN{it.sans.length === 1 ? "" : "s"}</span>
                  <span title={fullDate(it.createdAt)}>{timeAgo(it.createdAt)}</span>
                </div>
              </div>
              <div className="hist-actions" onClick={e => e.stopPropagation()}>
                <Button variant="ghost" size="sm" icon="refresh" onClick={() => { onRegenerate(it); push("Loaded into generator"); }} title="Reuse settings">Reuse</Button>
                <Button variant="ghost" size="sm" icon="trash" onClick={() => { onDelete(it.id); if (open === i) setOpen(null); push("Request deleted"); }} title="Delete" />
                <Button variant="ghost" size="sm" icon="chevron" onClick={() => setOpen(open === i ? null : i)} title="Details" />
              </div>
            </div>

            {open === i && (
              <div className="card fade-in" style={{ marginTop: -4, marginBottom: 4 }}>
                <div className="card-body stack">
                  <dl className="meta">
                    <dt>Common Name</dt><dd>{it.subject.CN}</dd>
                    <dt>Alt names</dt><dd>{it.sans.length ? it.sans.map(s => s.value).join(", ") : <span className="empty">none</span>}</dd>
                    <dt>Organization</dt><dd className={it.subject.O ? "" : "empty"}>{it.subject.O || "—"}</dd>
                    <dt>Created</dt><dd>{fullDate(it.createdAt)}</dd>
                  </dl>
                  <CodeBlock title={safeName(it.subject.CN) + ".csr"} value={it.csrPem}
                    onCopy={() => doCopy(it.csrPem, "CSR")}
                    onDownload={() => { download(safeName(it.subject.CN) + ".csr", it.csrPem); push("CSR downloaded"); }} />
                  {it.keyPem && (
                    <CodeBlock title={safeName(it.subject.CN) + ".key — private key"} value={it.keyPem}
                      onCopy={() => doCopy(it.keyPem, "Private key")}
                      onDownload={() => { download(safeName(it.subject.CN) + ".key", it.keyPem); push("Private key downloaded"); }} />
                  )}
                </div>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
