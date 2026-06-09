/* Shared UI primitives (ported from design components.jsx) */
import React, { useState, useCallback } from "react";

/* ---------- Icons ---------- */
const ICONS = {
  shield: "M12 2l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V5l8-3z",
  key: "M14 7a3 3 0 1 0-2.83 4H13l2 2 1.5-1.5L18 13l2-2-2-2H14zM10 11l-7 7v3h3l1-1v-2h2v-2h2l1-1.17",
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zM14 2v6h6M8 13h8M8 17h6",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.3-4.3",
  history: "M3 3v6h6M3.5 9A9 9 0 1 1 4 15M12 7v5l3 2",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.5 3.5 6 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-6-3.5-9s1-6.5 3.5-9z",
  asterisk: "M12 4v16M5 7l14 10M19 7L5 17",
  layers: "M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17l9 5 9-5",
  copy: "M9 9h10a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V9zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
  check: "M5 12l5 5L20 6",
  download: "M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2",
  trash: "M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M10 11v6M14 11v6",
  plus: "M12 5v14M5 12h14",
  x: "M6 6l12 12M18 6L6 18",
  alert: "M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  chevron: "M6 9l6 6 6-6",
  menu: "M3 6h18M3 12h18M3 18h18",
  lock: "M5 11h14a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1zM8 11V7a4 4 0 0 1 8 0v4",
  terminal: "M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM7 9l3 3-3 3M13 15h4",
  refresh: "M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  info: "M12 16v-4m0-4h.01M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
  server: "M4 4h16a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM4 14h16a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1zM7 7h.01M7 17h.01",
  spark: "M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2 2-6z",
  arrow: "M5 12h14M13 6l6 6-6 6",
  cert: "M9 12l2 2 4-4M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z",
  settings: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19.4 13a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 0 1-4 0v-.2a1.6 1.6 0 0 0-2.7-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 4.6 13H4.4a2 2 0 0 1 0-4h.2a1.6 1.6 0 0 0 1.1-2.7l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 2.7-1.1V2a2 2 0 0 1 4 0v.2a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0 1.1 2.7h.2a2 2 0 0 1 0 4h-.2a1.6 1.6 0 0 0-1.5 1z"
};

export function Icon({ name, ...rest }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
         strokeLinecap="round" strokeLinejoin="round" {...rest}>
      <path d={ICONS[name]} />
    </svg>
  );
}

export function Field({ label, optional, hint, error, children, htmlFor }) {
  return (
    <div className="field">
      {label && (
        <label htmlFor={htmlFor}>
          {label}{optional && <span className="opt">optional</span>}
        </label>
      )}
      {children}
      {hint && !error && <span className="hint">{hint}</span>}
      {error && <span className="field-err"><Icon name="alert" />{error}</span>}
    </div>
  );
}

export function TextInput({ value, onChange, error, mono, ...rest }) {
  return (
    <input className={"input" + (mono ? " mono" : "") + (error ? " err" : "")}
           value={value} onChange={e => onChange(e.target.value)} {...rest} />
  );
}

export function Select({ value, onChange, options, ...rest }) {
  return (
    <div className="select-wrap">
      <select className="select" value={value} onChange={e => onChange(e.target.value)} {...rest}>
        {options.map(o =>
          typeof o === "string"
            ? <option key={o} value={o}>{o}</option>
            : <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <Icon name="chevron" className="chev" />
    </div>
  );
}

export function Segmented({ value, onChange, options }) {
  return (
    <div className="seg" role="tablist">
      {options.map(o => {
        const val = typeof o === "string" ? o : o.value;
        const lbl = typeof o === "string" ? o : o.label;
        return (
          <button key={val} className={value === val ? "on" : ""} onClick={() => onChange(val)} role="tab" aria-selected={value === val}>
            {lbl}
          </button>
        );
      })}
    </div>
  );
}

export function Button({ variant = "ghost", size, block, icon, loading, children, ...rest }) {
  const cls = ["btn", "btn-" + variant];
  if (size) cls.push("btn-" + size);
  if (block) cls.push("btn-block");
  if (!children) cls.push("btn-icon");
  return (
    <button className={cls.join(" ")} disabled={loading || rest.disabled} {...rest}>
      {loading ? <span className="spinner" /> : icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

export function CodeBlock({ title, value, onCopy, onDownload, cmd, dots = true }) {
  return (
    <div className={"code" + (cmd ? " cmd" : "")}>
      <div className="code-head">
        {dots && <>
          <span className="code-dot" style={{ background: "#ff5f57" }} />
          <span className="code-dot" style={{ background: "#febc2e" }} />
          <span className="code-dot" style={{ background: "#28c840" }} />
        </>}
        <span className="code-title">{title}</span>
        <div className="code-actions">
          {onCopy && <button className="cbtn" onClick={onCopy}><Icon name="copy" />Copy</button>}
          {onDownload && <button className="cbtn" onClick={onDownload}><Icon name="download" />Download</button>}
        </div>
      </div>
      <pre>{value}</pre>
    </div>
  );
}

export function Pill({ kind = "neutral", icon, children }) {
  return <span className={"pill " + kind}>{icon && <Icon name={icon} />}{children}</span>;
}

export function useToasts() {
  const [toasts, setToasts] = useState([]);
  const push = useCallback((msg, kind = "ok") => {
    const id = Math.random().toString(36).slice(2);
    setToasts(t => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 2600);
  }, []);
  return [toasts, push];
}

export function ToastHost({ toasts }) {
  return (
    <div className="toast-wrap">
      {toasts.map(t => (
        <div key={t.id} className={"toast " + t.kind}>
          <Icon name={t.kind === "err" ? "alert" : "check"} />{t.msg}
        </div>
      ))}
    </div>
  );
}

export function Switch({ value, onChange, label }) {
  return (
    <button type="button" className={"switch" + (value ? " on" : "")} role="switch" aria-checked={!!value}
      aria-label={label} onClick={() => onChange(!value)}>
      <span className="switch-knob" />
    </button>
  );
}
