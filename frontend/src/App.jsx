/* App shell, navigation, theming, history, tweaks (ported from design app.jsx) */
import React, { useState, useEffect } from "react";
import { Icon, Button, ToastHost, useToasts } from "./components/ui.jsx";
import { TweaksPanel } from "./components/TweaksPanel.jsx";
import { useTweaks } from "./hooks/useTweaks.js";
import { GenerateView } from "./views/GenerateView.jsx";
import { DecodeView } from "./views/DecodeView.jsx";
import { QuantumScanView } from "./views/QuantumScanView.jsx";
import { CompareView } from "./views/CompareView.jsx";
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
  { id: "quantum", label: "Quantum Scan", icon: "spark" },
  { id: "compare", label: "Compare", icon: "layers" },
  { id: "history", label: "History", icon: "history" },
  { id: "server", label: "Server / API", icon: "server" }
];

// URL routing (History API, no router lib)
const VIEW_PATH = { generate: "/", decode: "/decode", quantum: "/quantum", compare: "/compare", history: "/history", server: "/server" };
const PATH_VIEW = { "/decode": "decode", "/quantum": "quantum", "/compare": "compare", "/history": "history", "/server": "server" };

// Per-route SEO: Googlebot renders the SPA, so updating title/description/canonical
// on navigation gives each view its own indexable metadata.
const SITE = "https://pqcert.avinashchavan.com";
const ROUTE_SEO = {
  generate: { title: "CSR Generator — RSA, ECDSA & Post-Quantum (ML-DSA) CSRs | PQCert",
    desc: "Free online CSR generator: create Certificate Signing Requests with RSA, ECDSA, Ed25519 or post-quantum ML-DSA / SLH-DSA / Falcon keys." },
  decode: { title: "CSR Decoder — Decode & Verify a PKCS#10 CSR Online | PQCert",
    desc: "Decode any Certificate Signing Request: read the subject, SANs, key strength, signature validity and extensions, and check it matches your private key." },
  quantum: { title: "Quantum-Readiness Scanner — Is Your Site Quantum-Safe? | PQCert",
    desc: "Scan any live domain, CSR or certificate for 'harvest now, decrypt later' risk and get a post-quantum letter grade with a migration plan." },
  compare: { title: "Compare Two CSRs — Field-by-Field Diff | PQCert",
    desc: "Diff two Certificate Signing Requests side by side — subject, SANs, key and extensions — before you submit to a CA." },
  history: { title: "CSR History | PQCert",
    desc: "Review your recently generated Certificate Signing Requests (CSR and metadata only — never private keys)." },
  server: { title: "Server / API Contract | PQCert",
    desc: "Connect your backend and view the REST API contract PQCert implements for CSR generation, decoding and quantum scanning." },
  notfound: { title: "Page not found | PQCert", desc: "That page doesn't exist." }
};
function applyRouteSeo(view) {
  const s = ROUTE_SEO[view] || ROUTE_SEO.generate;
  document.title = s.title;
  const setMeta = (name, val) => {
    let el = document.querySelector(`meta[name="${name}"]`);
    if (!el) { el = document.createElement("meta"); el.setAttribute("name", name); document.head.appendChild(el); }
    el.setAttribute("content", val);
  };
  setMeta("description", s.desc);
  let link = document.querySelector('link[rel="canonical"]');
  if (!link) { link = document.createElement("link"); link.setAttribute("rel", "canonical"); document.head.appendChild(link); }
  link.setAttribute("href", SITE + (VIEW_PATH[view] || "/"));
}
function pathToView() {
  const p = (location.pathname || "/").replace(/\/+$/, "") || "/";
  if (p === "/") return "generate";
  return PATH_VIEW[p] || "notfound";
}
function initialView() {
  const q = new URLSearchParams(location.search);
  if (q.get("share")) return "decode";
  if (q.get("scan")) return "quantum";
  return pathToView();
}

export default function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [view, setView] = useState(initialView);
  const [navOpen, setNavOpen] = useState(false);
  const [history, setHistory] = useState([]);
  const [seed, setSeed] = useState(null);
  const [apiTick, setApiTick] = useState(0);
  const [toasts, push] = useToasts();
  const refreshApi = () => setApiTick(x => x + 1);
  const apiMode = api.mode();

  const [seedCsr, setSeedCsr] = useState(null);
  const [seedHost, setSeedHost] = useState(null);
  const reloadHistory = () => api.historyList().then(setHistory).catch(() => {});

  // deep links: /?share=<id> → read-only Decode · /?scan=<domain> → run a quantum scan
  useEffect(() => {
    const q = new URLSearchParams(location.search);
    const id = q.get("share");
    const scanHost = q.get("scan");
    if (id) {
      setView("decode");
      api.shareGet(id).then(d => setSeedCsr(d.csr)).catch(() => push("That review link wasn't found (it may have expired).", "err"));
    } else if (scanHost) {
      setView("quantum");
      setSeedHost(scanHost);
    }
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

  // Per-route title / description / canonical (updated on navigation for SEO).
  useEffect(() => { applyRouteSeo(view); }, [view]);

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

  function go(v) {
    setView(v); setNavOpen(false);
    const path = VIEW_PATH[v] || "/";
    // window.history — NOT the `history` state var above (which shadows it)
    try { if (location.pathname !== path || location.search) window.history.pushState({ v }, "", path); } catch (e) {}
  }

  // browser back/forward → sync view from the URL
  useEffect(() => {
    const onPop = () => setView(pathToView());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const accentChoices = ACCENTS[t.look] || ACCENTS.slate;
  const current = NAV.find(n => n.id === view) || { label: "Page not found" };
  const subtitle = {
    generate: apiMode === "demo" ? "Build a signing request — running the in-browser demo until your backend is connected." : "Build a signing request; your backend creates the key and signs it.",
    decode: "Inspect and verify any existing PKCS#10 request.",
    quantum: "Grade a live site, CSR or certificate against the post-quantum threat.",
    compare: "Diff two CSRs field by field before submitting.",
    history: apiMode === "connected" ? "Saved requests stored on " + api.host() + " (CSR + metadata only)." : "Saved requests from this browser.",
    server: "Connect your backend and view the API contract it must implement.",
    notfound: "That page doesn't exist."
  }[view];

  return (
    <div className="app">
      <aside className={"sidebar" + (navOpen ? " open" : "")}>
        <div className="brand" onClick={() => go("generate")} style={{ cursor: "pointer" }}
          role="link" tabIndex={0} title="Home"
          onKeyDown={e => { if (e.key === "Enter") go("generate"); }}>
          <span className="brand-mark"><Icon name="shield" /></span>
          <div>
            <div className="brand-name">PQCert</div>
            <div className="brand-sub">post-quantum CSR &amp; cert toolkit</div>
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
          {view === "quantum" && <QuantumScanView push={push} seedHost={seedHost}
            onGenerateHybrid={(target) => { setSeed({ cn: /^[a-zA-Z0-9.-]+$/.test(target || "") ? target : "", _ts: Date.now() }); go("generate"); push("Use the Hybrid PQC button below"); }} />}
          {view === "compare" && <CompareView push={push} />}
          {view === "history" && <HistoryView items={history} onDelete={deleteItem} onClear={clearAll} onRegenerate={regenerate} push={push} />}
          {view === "server" && <ServerView push={push} onConfigChange={refreshApi} />}
          {view === "notfound" && (
            <div className="fade-in">
              <div className="result-empty" style={{ maxWidth: 520, margin: "40px auto" }}>
                <span className="big" style={{ width: 72, height: 72, fontFamily: "var(--font-head)", fontWeight: 700, fontSize: 30, color: "var(--accent)" }}>404</span>
                <h4>Page not found</h4>
                <p><code>{typeof location !== "undefined" ? location.pathname : ""}</code> doesn't exist. It may have moved, or the link is wrong.</p>
                <div style={{ display: "flex", gap: 10, marginTop: 6, flexWrap: "wrap", justifyContent: "center" }}>
                  <Button variant="primary" icon="cert" onClick={() => go("generate")}>Go to the generator</Button>
                  <Button variant="ghost" icon="spark" onClick={() => go("quantum")}>Quantum scan</Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      <ToastHost toasts={toasts} />
      <TweaksPanel tweaks={t} setTweak={setTweak} accentChoices={accentChoices} />
    </div>
  );
}
