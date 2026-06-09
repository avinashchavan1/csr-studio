/* Floating "Tweaks" panel — theme / accent / density / grid (the design's "variations"). */
import React, { useState } from "react";
import { Icon, Switch } from "./ui.jsx";

export function TweaksPanel({ tweaks, setTweak, accentChoices }) {
  const [open, setOpen] = useState(false);
  const t = tweaks;

  return (
    <>
      <button
        className="btn btn-ghost"
        onClick={() => setOpen(o => !o)}
        title="Tweaks"
        style={{ position: "fixed", right: 18, bottom: 18, zIndex: 150, boxShadow: "var(--shadow-md)" }}
      >
        <Icon name="settings" /> Tweaks
      </button>

      {open && (
        <div
          className="card fade-in"
          style={{ position: "fixed", right: 18, bottom: 70, zIndex: 150, width: 280, boxShadow: "var(--shadow-lg)" }}
        >
          <div className="card-head">
            <span className="ico"><Icon name="settings" /></span>
            <h3>Tweaks</h3>
            <button className="btn btn-ghost btn-icon" style={{ marginLeft: "auto" }} onClick={() => setOpen(false)}>
              <Icon name="x" />
            </button>
          </div>
          <div className="card-body fgroup">
            <div className="field">
              <label>Theme</label>
              <div className="seg">
                {["slate", "saas", "terminal"].map(v => (
                  <button key={v} className={t.look === v ? "on" : ""}
                    onClick={() => setTweak({ look: v, accent: "" })}>
                    {v[0].toUpperCase() + v.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            <div className="field">
              <label>Accent</label>
              <div style={{ display: "flex", gap: 8 }}>
                {accentChoices.map(c => (
                  <button key={c} onClick={() => setTweak("accent", c)} aria-label={"accent " + c}
                    style={{
                      width: 26, height: 26, borderRadius: 7, background: c, cursor: "pointer",
                      border: (t.accent || accentChoices[0]) === c ? "2px solid var(--text)" : "1px solid var(--border)"
                    }} />
                ))}
              </div>
            </div>

            <div className="field">
              <label>Density</label>
              <div className="seg">
                {["compact", "regular"].map(v => (
                  <button key={v} className={t.density === v ? "on" : ""} onClick={() => setTweak("density", v)}>
                    {v[0].toUpperCase() + v.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            <div className="set-row" style={{ borderTop: 0, paddingBottom: 0 }}>
              <div className="set-main">
                <div className="set-title">Grid background</div>
              </div>
              <div className="set-ctrl">
                <Switch value={t.grid} onChange={v => setTweak("grid", v)} label="Grid background" />
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
