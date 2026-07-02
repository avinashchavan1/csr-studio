/* App shell, navigation, theming, history, tweaks (ported from design app.jsx) */
import React, { useState, useEffect } from "react";
import { Icon, Button, ToastHost, useToasts } from "./components/ui.jsx";
import { TweaksPanel } from "./components/TweaksPanel.jsx";
import { useTweaks } from "./hooks/useTweaks.js";
import { GenerateView } from "./views/GenerateView.jsx";
import { DecodeView } from "./views/DecodeView.jsx";
import { HistoryView } from "./views/HistoryView.jsx";
import { ServerView } from "./views/ServerView.jsx";
import * as api from "./lib/api.js";

const TWEAK_DEFAULTS = { look: "slate", accent: "", density: "regular", grid: true };

const ACCENTS = {
  slate: ["#2563eb", "#0d9488", "#7c3aed", "#e11d48"],
  saas: ["#6d3fe0", "#2563eb", "#db2777", "#0d9488"],
  terminal: ["#46e3a0", "#7dd3fc", "#f6c453", "#ff6b81"]
};

const NAV = [
  { id: "generate", label: "Generate CSR", icon: "cert" },
  { id: "decode", label: "Decode / Inspect", icon: "search" },
  { id: "history", label: "History", icon: "history" },
  { id: "server", label: "Server / API", icon: "server" }
];

export default function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [view, setView] = useState("generate");
  const [navOpen, setNavOpen] = useState(false);
  const [history, setHistory] = useState([]);
  const [seed, setSeed] = useState(null);
  const [apiTick, setApiTick] = useState(0);
  const [toasts, push] = useToasts();
  const refreshApi = () => setApiTick(x => x + 1);
  const apiMode = api.mode();

  const [seedCsr, setSeedCsr] = useState(null);
  const reloadHistory = () => api.historyList().then(setHistory).catch(() => {});

  // review share link: /?share=<id> → open the CSR read-only in Decode
  useEffect(() => {
    const id = new URLSearchParams(location.search).get("share");
    if (!id) return;
    setView("decode");
    api.shareGet(id).then(d => setSeedCsr(d.csr)).catch(() => push("That review link wasn't found (it may have expired).", "err"));
  }, []);

  // load history on mount and whenever the API config (demo/connected) changes
  useEffect(() => { let live = true; api.historyList().then(h => { if (live) setHistory(h); }).catch(() => {}); return () => { live = false; }; }, [apiTick]);

  useEffect(() => {
    const r = document.documentElement;
    r.setAttribute("data-theme", t.look || "slate");
    if (t.accent) r.style.setProperty("--accent", t.accent);
    else r.style.removeProperty("--accent");
    document.body.style.fontSize = t.density === "compact" ? "14px" : "15px";
    if (!t.grid) document.body.style.backgroundImage = "none";
    else document.body.style.removeProperty("background-image");
  }, [t.look, t.accent, t.density, t.grid]);

  function onGenerated(res) { api.historySave(res).then(reloadHistory).catch(() => {}); }
  function deleteItem(id) { api.historyDelete(id).then(reloadHistory).catch(() => {}); }
  function clearAll() { api.historyClear().then(reloadHistory).catch(() => {}); }
  function regenerate(it) {
    setSeed({
      cn: it.subject.CN || "", sans: (it.sans || []).filter(s => s.value !== it.subject.CN),
      O: it.subject.O || "", OU: it.subject.OU || "", L: it.subject.L || "",
      ST: it.subject.ST || "", C: it.subject.C || "US", email: it.subject.email || "",
      keyType: it.keyType || (it.keyKind === "ECDSA" ? "ecdsa" : "rsa"),
      size: it.size || (it.keyKind === "ECDSA" ? "P-256" : "2048"),
      pqcAlgo: it.keyType === "pqc" ? (it.keyLabel || "ML-DSA-65") : "ML-DSA-65",
      hash: it.hash || it.sigAlg || "SHA-256",
      keyFormat: it.keyFormat === "PKCS#1" ? "pkcs1" : "pkcs8",
      _ts: Date.now()
    });
    go("generate");
  }

  function go(v) { setView(v); setNavOpen(false); }

  const accentChoices = ACCENTS[t.look] || ACCENTS.slate;
  const current = NAV.find(n => n.id === view);
  const subtitle = {
    generate: apiMode === "demo" ? "Build a signing request — running the in-browser demo until your backend is connected." : "Build a signing request; your backend creates the key and signs it.",
    decode: "Inspect and verify any existing PKCS#10 request.",
    history: apiMode === "connected" ? "Saved requests stored on " + api.host() + " (CSR + metadata only)." : "Saved requests from this browser.",
    server: "Connect your backend and view the API contract it must implement."
  }[view];

  return (
    <div className="app">
      <aside className={"sidebar" + (navOpen ? " open" : "")}>
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" /></span>
          <div>
            <div className="brand-name">CSR Studio</div>
            <div className="brand-sub">certificate signing requests</div>
          </div>
        </div>
        <nav className="nav">
          <div className="nav-label">Tools</div>
          {NAV.map(n => (
            <div key={n.id} className={"nav-item" + (view === n.id ? " active" : "")} onClick={() => go(n.id)}>
              <Icon name={n.icon} />{n.label}
              {n.id === "history" && history.length > 0 && <span className="kbd">{history.length}</span>}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="privacy-badge" onClick={() => go("server")} style={{ cursor: "pointer" }} title="Backend connection settings">
            <Icon name={apiMode === "connected" ? "server" : "terminal"} />
            <span>{apiMode === "connected"
              ? <><b>Connected.</b> Requests go to {api.host()}. Keys are generated server-side.</>
              : <><b>Demo mode.</b> Running the in-browser reference engine. Connect your backend in Server / API.</>}</span>
          </div>
        </div>
      </aside>
      <div className={"scrim" + (navOpen ? " show" : "")} onClick={() => setNavOpen(false)} />

      <main className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setNavOpen(true)} aria-label="Menu"><Icon name="menu" /></button>
          <div>
            <h1>{current.label}</h1>
            <div className="sub">{subtitle}</div>
          </div>
          <div className="topbar-spacer" />
          <button className={"conn-chip " + apiMode} onClick={() => go("server")} title="Backend connection">
            <span className="conn-dot" />
            {apiMode === "connected" ? api.host() : "Demo mode"}
          </button>
          {view !== "generate" && view !== "server" &&
            <Button variant="soft" icon="plus" onClick={() => { setSeed(null); go("generate"); }}>New CSR</Button>}
        </header>

        <div className={"content" + (view === "history" ? " narrow" : "")}>
          {view === "generate" && <GenerateView key={seed && seed._ts} seed={seed} onGenerated={onGenerated} push={push} />}
          {view === "decode" && <DecodeView push={push} seedCsr={seedCsr} />}
          {view === "history" && <HistoryView items={history} onDelete={deleteItem} onClear={clearAll} onRegenerate={regenerate} push={push} />}
          {view === "server" && <ServerView push={push} onConfigChange={refreshApi} />}
        </div>
      </main>

      <ToastHost toasts={toasts} />
      <TweaksPanel tweaks={t} setTweak={setTweak} accentChoices={accentChoices} />
    </div>
  );
}
