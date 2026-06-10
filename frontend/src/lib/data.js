/* Static data + small utilities (ported from design data.js) */

// ISO 3166-1 alpha-2, common subset
export const COUNTRIES = [
  ["US", "United States"], ["GB", "United Kingdom"], ["CA", "Canada"], ["AU", "Australia"],
  ["DE", "Germany"], ["FR", "France"], ["NL", "Netherlands"], ["ES", "Spain"], ["IT", "Italy"],
  ["PT", "Portugal"], ["IE", "Ireland"], ["BE", "Belgium"], ["CH", "Switzerland"], ["AT", "Austria"],
  ["SE", "Sweden"], ["NO", "Norway"], ["DK", "Denmark"], ["FI", "Finland"], ["PL", "Poland"],
  ["CZ", "Czechia"], ["RO", "Romania"], ["GR", "Greece"], ["HU", "Hungary"], ["UA", "Ukraine"],
  ["RU", "Russia"], ["TR", "Turkey"], ["IL", "Israel"], ["AE", "United Arab Emirates"],
  ["SA", "Saudi Arabia"], ["ZA", "South Africa"], ["NG", "Nigeria"], ["KE", "Kenya"], ["EG", "Egypt"],
  ["IN", "India"], ["PK", "Pakistan"], ["BD", "Bangladesh"], ["CN", "China"], ["HK", "Hong Kong"],
  ["TW", "Taiwan"], ["JP", "Japan"], ["KR", "South Korea"], ["SG", "Singapore"], ["MY", "Malaysia"],
  ["TH", "Thailand"], ["VN", "Vietnam"], ["ID", "Indonesia"], ["PH", "Philippines"], ["NZ", "New Zealand"],
  ["BR", "Brazil"], ["MX", "Mexico"], ["AR", "Argentina"], ["CL", "Chile"], ["CO", "Colombia"],
  ["PE", "Peru"], ["VE", "Venezuela"], ["UY", "Uruguay"], ["CR", "Costa Rica"], ["PA", "Panama"]
].map(([code, name]) => ({ code, name }));

export const KEY_PRESETS = {
  rsa: [
    { value: "2048", label: "2048-bit", note: "Standard · widely compatible" },
    { value: "3072", label: "3072-bit", note: "Stronger · ~128-bit security" },
    { value: "4096", label: "4096-bit", note: "Maximum · slower handshakes" }
  ],
  ecdsa: [
    { value: "P-256", label: "P-256", note: "prime256v1 · ~128-bit security" },
    { value: "P-384", label: "P-384", note: "secp384r1 · ~192-bit security" },
    { value: "P-521", label: "P-521", note: "secp521r1 · ~256-bit security" }
  ]
};

export const HASHES = [
  { value: "SHA-256", label: "SHA-256" },
  { value: "SHA-384", label: "SHA-384" },
  { value: "SHA-512", label: "SHA-512" }
];

export const PRESETS = [
  { id: "single", icon: "globe", title: "Single domain", desc: "One hostname, e.g. example.com",
    apply: () => ({ sans: [] }) },
  { id: "www", icon: "globe", title: "Apex + www", desc: "example.com and www.example.com",
    apply: (cn) => ({ sans: cn ? [{ type: "DNS", value: "www." + cn.replace(/^www\./, "") }] : [] }) },
  { id: "wildcard", icon: "asterisk", title: "Wildcard", desc: "*.example.com covers all sub-domains",
    apply: (cn) => ({ cn: cn ? "*." + cn.replace(/^\*\./, "").replace(/^www\./, "") : "", sans: [] }) },
  { id: "multi", icon: "layers", title: "Multi-domain (SAN)", desc: "Several hostnames on one cert",
    apply: (cn) => ({ sans: [{ type: "DNS", value: "api." + (cn || "example.com") }, { type: "DNS", value: "mail." + (cn || "example.com") }] }) }
];

// ---- utilities ----
export function classifySAN(value) {
  const v = (value || "").trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "IP";
  if (/:/.test(v) && /^[0-9a-f:]+$/i.test(v)) return "IP";
  return "DNS";
}

export function isValidDomain(v) {
  if (!v) return false;
  if (v.startsWith("*.")) v = v.slice(2);
  return /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i.test(v)
    || /^[a-z0-9-]{1,63}$/i.test(v); // allow bare host / internal name
}

export function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((res, rej) => {
    try {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta); res();
    } catch (e) { rej(e); }
  });
}

export function download(filename, text) {
  const blob = new Blob([text], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function safeName(cn) {
  return (cn || "certificate").replace(/^\*\./, "wildcard_").replace(/[^a-z0-9.-]/gi, "_").replace(/^_+|_+$/g, "") || "certificate";
}

export function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60); if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60); if (h < 24) return h + "h ago";
  const d = Math.floor(h / 24); if (d < 30) return d + "d ago";
  return new Date(ts).toLocaleDateString();
}

export function fullDate(ts) {
  return new Date(ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
