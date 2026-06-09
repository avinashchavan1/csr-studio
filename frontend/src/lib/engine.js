/* ============================================================
   engine.js — in-browser reference CSR engine for DEMO mode
   RSA  : node-forge (real PKCS#10 + private key)
   ECDSA: WebCrypto keygen + compact DER PKCS#10 builder
   (ported from design engine.js → ES module)
   ============================================================ */
import forge from "node-forge";
import { safeName } from "./data.js";

const OID = {
  CN: "2.5.4.3", C: "2.5.4.6", ST: "2.5.4.8", L: "2.5.4.7",
  O: "2.5.4.10", OU: "2.5.4.11", EMAIL: "1.2.840.113549.1.9.1",
  EXT_REQ: "1.2.840.113549.1.9.14", SAN: "2.5.29.17",
  ECDSA_SHA256: "1.2.840.10045.4.3.2", ECDSA_SHA384: "1.2.840.10045.4.3.3",
  ECDSA_SHA512: "1.2.840.10045.4.3.4"
};

/* ---------- tiny DER toolkit ---------- */
const u8 = (a) => Uint8Array.from(a);
function encLen(n) {
  if (n < 128) return [n];
  const out = []; let m = n;
  while (m > 0) { out.unshift(m & 0xff); m >>= 8; }
  return [0x80 | out.length, ...out];
}
function cat(arrs) {
  let len = 0; arrs.forEach(a => len += a.length);
  const out = new Uint8Array(len); let off = 0;
  arrs.forEach(a => { out.set(a, off); off += a.length; });
  return out;
}
function tlv(tag, content) { return cat([u8([tag]), u8(encLen(content.length)), content]); }
const SEQ = (...c) => tlv(0x30, cat(c));
const SET = (...c) => tlv(0x31, cat(c));
const CTX = (n, content) => tlv(0xA0 | n, content);
const CTXp = (n, content) => tlv(0x80 | n, content);
const OCTET = (c) => tlv(0x04, c);
const BIT = (c) => tlv(0x03, cat([u8([0]), c]));
const PRINT = (s) => tlv(0x13, u8([...s].map(ch => ch.charCodeAt(0))));
const UTF8 = (s) => tlv(0x0c, new TextEncoder().encode(s));
const IA5 = (s) => tlv(0x16, u8([...s].map(ch => ch.charCodeAt(0))));
function INT(bytes) {
  let b = Array.from(bytes);
  while (b.length > 1 && b[0] === 0) b.shift();
  if (b[0] & 0x80) b.unshift(0);
  return tlv(0x02, u8(b));
}
const INT0 = () => tlv(0x02, u8([0]));
function OIDenc(str) {
  const p = str.split(".").map(Number);
  const bytes = [40 * p[0] + p[1]];
  for (let i = 2; i < p.length; i++) {
    let v = p[i]; const stack = [v & 0x7f]; v >>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>= 7; }
    bytes.push(...stack);
  }
  return tlv(0x06, u8(bytes));
}

function rdn(oid, valueNode) { return SET(SEQ(OIDenc(oid), valueNode)); }

function buildName(subj) {
  const parts = [];
  if (subj.C) parts.push(rdn(OID.C, PRINT(subj.C)));
  if (subj.ST) parts.push(rdn(OID.ST, UTF8(subj.ST)));
  if (subj.L) parts.push(rdn(OID.L, UTF8(subj.L)));
  if (subj.O) parts.push(rdn(OID.O, UTF8(subj.O)));
  if (subj.OU) parts.push(rdn(OID.OU, UTF8(subj.OU)));
  if (subj.CN) parts.push(rdn(OID.CN, UTF8(subj.CN)));
  if (subj.email) parts.push(rdn(OID.EMAIL, IA5(subj.email)));
  return SEQ(...parts);
}

function ipv4ToBytes(s) { return u8(s.split(".").map(n => parseInt(n, 10) & 0xff)); }

function buildSANExt(sans) {
  const names = sans.map(s =>
    s.type === "IP" ? CTXp(7, ipv4ToBytes(s.value)) : CTXp(2, u8([...s.value].map(c => c.charCodeAt(0))))
  );
  const sanValue = SEQ(...names);
  const ext = SEQ(OIDenc(OID.SAN), OCTET(sanValue));
  return SEQ(OIDenc(OID.EXT_REQ), SET(SEQ(ext)));
}

function pemWrap(der, label) {
  let bin = ""; der.forEach(b => bin += String.fromCharCode(b));
  const b64 = btoa(bin).replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

function rawSigToDer(raw) {
  const half = raw.length / 2;
  return SEQ(INT(raw.slice(0, half)), INT(raw.slice(half)));
}

/* ---------- ECDSA path ---------- */
async function generateECDSA(opts) {
  const curve = opts.size;
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  const subjectName = buildName(opts.subject);
  const attrs = opts.sans && opts.sans.length
    ? CTX(0, buildSANExt(opts.sans)) : CTX(0, new Uint8Array(0));
  const cri = SEQ(INT0(), subjectName, spki, attrs);

  const hash = opts.hash;
  const sigRaw = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash }, kp.privateKey, cri
  ));
  const sigAlgOid = hash === "SHA-384" ? OID.ECDSA_SHA384
    : hash === "SHA-512" ? OID.ECDSA_SHA512 : OID.ECDSA_SHA256;
  const csr = SEQ(cri, SEQ(OIDenc(sigAlgOid)), BIT(rawSigToDer(sigRaw)));

  return {
    csrPem: pemWrap(csr, "CERTIFICATE REQUEST"),
    keyPem: pemWrap(pkcs8, "PRIVATE KEY"),
    keyLabel: "ECDSA " + curve,
    keyFormat: "PKCS#8",
    keyKind: "ECDSA", keyDetail: curve, bits: curve === "P-384" ? 384 : 256
  };
}

/* ---------- RSA path (node-forge) ---------- */
function generateRSA(opts) {
  return new Promise((resolve, reject) => {
    const bits = parseInt(opts.size, 10);
    forge.pki.rsa.generateKeyPair({ bits }, (err, keys) => {
      if (err) return reject(err);
      try {
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;
        const s = opts.subject;
        const attrsName = [];
        if (s.CN) attrsName.push({ name: "commonName", value: s.CN });
        if (s.O) attrsName.push({ name: "organizationName", value: s.O });
        if (s.OU) attrsName.push({ shortName: "OU", value: s.OU });
        if (s.L) attrsName.push({ name: "localityName", value: s.L });
        if (s.ST) attrsName.push({ shortName: "ST", value: s.ST });
        if (s.C) attrsName.push({ name: "countryName", value: s.C });
        if (s.email) attrsName.push({ name: "emailAddress", value: s.email });
        csr.setSubject(attrsName);

        if (opts.sans && opts.sans.length) {
          csr.setAttributes([{
            name: "extensionRequest",
            extensions: [{
              name: "subjectAltName",
              altNames: opts.sans.map(san =>
                san.type === "IP" ? { type: 7, ip: san.value } : { type: 2, value: san.value })
            }]
          }]);
        }
        const md = { "SHA-256": forge.md.sha256, "SHA-384": forge.md.sha384, "SHA-512": forge.md.sha512 }[opts.hash] || forge.md.sha256;
        csr.sign(keys.privateKey, md.create());

        let keyPem;
        if (opts.keyFormat === "pkcs1") {
          keyPem = forge.pki.privateKeyToPem(keys.privateKey);
        } else {
          const info = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey));
          keyPem = forge.pki.privateKeyInfoToPem(info);
        }

        resolve({
          csrPem: forge.pki.certificationRequestToPem(csr),
          keyPem,
          keyLabel: "RSA " + bits,
          keyFormat: opts.keyFormat === "pkcs1" ? "PKCS#1" : "PKCS#8",
          keyKind: "RSA", keyDetail: bits + "-bit", bits
        });
      } catch (e) { reject(e); }
    });
  });
}

export async function generate(opts) {
  const base = opts.keyType === "ecdsa" ? await generateECDSA(opts) : await generateRSA(opts);
  return Object.assign(base, {
    sigAlg: opts.hash, hash: opts.hash, keyType: opts.keyType, size: opts.size,
    subject: opts.subject, sans: opts.sans || [], createdAt: Date.now()
  });
}

/* ---------- decode ---------- */
const SUBJ_OID = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L",
  "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "email"
};
const CURVE_OID = {
  "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1"
};

function decodeManual(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = forge.util.decode64(b64);
  const asn1 = forge.asn1.fromDer(der);
  const cri = asn1.value[0];
  const subject = { CN: "", O: "", OU: "", L: "", ST: "", C: "", email: "" };
  (cri.value[1].value || []).forEach(rdnSet => {
    (rdnSet.value || []).forEach(seq => {
      try {
        const oid = forge.asn1.derToOid(seq.value[0].value);
        if (SUBJ_OID[oid]) subject[SUBJ_OID[oid]] = seq.value[1].value;
      } catch (e) {}
    });
  });
  let keyKind = "Unknown", keyDetail = "";
  try {
    const spki = cri.value[2];
    const alg = forge.asn1.derToOid(spki.value[0].value[0].value);
    if (alg === "1.2.840.10045.2.1") {
      keyKind = "ECDSA";
      const curve = forge.asn1.derToOid(spki.value[0].value[1].value);
      keyDetail = CURVE_OID[curve] || curve;
    } else if (alg === "1.2.840.113549.1.1.1") {
      keyKind = "RSA";
    }
  } catch (e) {}
  let sans = [];
  try {
    const attrs = cri.value[3];
    (attrs.value || []).forEach(attr => {
      const aoid = forge.asn1.derToOid(attr.value[0].value);
      if (aoid !== OID.EXT_REQ) return;
      attr.value[1].value.forEach(extSeq => {
        extSeq.value.forEach(ext => {
          const eoid = forge.asn1.derToOid(ext.value[0].value);
          if (eoid !== OID.SAN) return;
          const inner = forge.asn1.fromDer(ext.value[1].value);
          inner.value.forEach(gn => {
            const tag = gn.type;
            if (tag === 2) sans.push({ type: "DNS", value: gn.value });
            else if (tag === 7) {
              const bytes = gn.value;
              if (bytes.length === 4) sans.push({ type: "IP", value: Array.from(bytes, c => c.charCodeAt(0)).join(".") });
            }
          });
        });
      });
    });
  } catch (e) {}
  return { subject, sans, bits: null, keyKind, keyDetail, verified: null, sigAlg: keyKind === "ECDSA" ? "ECDSA (signature not re-checked)" : "", raw: pem.trim() };
}

export function decode(pem) {
  let csr;
  try {
    csr = forge.pki.certificationRequestFromPem(pem);
  } catch (e) {
    return decodeManual(pem);
  }
  const get = (sn, n) => {
    const f = csr.subject.getField(sn) || (n && csr.subject.getField(n));
    return f ? f.value : "";
  };
  const subject = {
    CN: get("CN", "commonName"), O: get("O", "organizationName"),
    OU: get("OU", "organizationalUnitName"), L: get("L", "localityName"),
    ST: get("ST", "stateOrProvinceName"), C: get("C", "countryName"),
    email: get("E", "emailAddress")
  };
  let sans = [];
  const extReq = (csr.attributes || []).find(a => a.name === "extensionRequest" || a.type === "1.2.840.113549.1.9.14");
  if (extReq && extReq.extensions) {
    const san = extReq.extensions.find(e => e.name === "subjectAltName");
    if (san && san.altNames) {
      sans = san.altNames.map(a => ({ type: a.type === 7 ? "IP" : "DNS", value: a.ip || a.value }));
    }
  }
  let bits = null, keyKind = "RSA", keyDetail = "";
  try { bits = csr.publicKey.n.bitLength(); keyDetail = bits + "-bit"; } catch (e) {}
  let verified = false;
  try { verified = csr.verify(); } catch (e) { verified = false; }
  let sigAlg = "";
  try {
    const oid = csr.signatureOid;
    sigAlg = forge.pki.oids[oid] || oid || "";
  } catch (e) {}
  return { subject, sans, bits, keyKind, keyDetail, verified, sigAlg, raw: pem.trim() };
}

/* ---------- openssl command ---------- */
export function opensslCommand(opts) {
  const s = opts.subject || {};
  const order = [["C", s.C], ["ST", s.ST], ["L", s.L], ["O", s.O], ["OU", s.OU], ["CN", s.CN]];
  const subj = order.filter(([, v]) => v).map(([k, v]) => `/${k}=${v}`).join("");
  let keyspec, keyfile = safeName(s.CN) + ".key";
  let csrfile = safeName(s.CN) + ".csr";
  if (opts.keyType === "ecdsa") {
    keyspec = `-newkey ec -pkeyopt ec_paramgen_curve:${opts.size === "P-384" ? "secp384r1" : "prime256v1"}`;
  } else {
    keyspec = `-newkey rsa:${opts.size}`;
  }
  const hashFlag = "-" + (opts.hash || "SHA-256").toLowerCase().replace("-", "");
  let cmd = `openssl req -new ${keyspec} -nodes ${hashFlag} \\\n` +
    `  -keyout ${keyfile} \\\n` +
    `  -out ${csrfile} \\\n` +
    `  -subj "${subj || "/CN=example.com"}"`;
  if (opts.sans && opts.sans.length) {
    const all = opts.sans.map(x => `${x.type}:${x.value}`).join(",");
    cmd += ` \\\n  -addext "subjectAltName=${all}"`;
  }
  return cmd;
}

/* ---------- verify CSR matches a private key (RSA) ---------- */
export function keyMatch(csrPem, keyPem) {
  let csr;
  try { csr = forge.pki.certificationRequestFromPem(csrPem); }
  catch (e) { return { supported: false, reason: "csr", msg: "This inspector can only match RSA key pairs. The CSR uses a key type (e.g. ECDSA) it can't read." }; }
  let priv;
  try { priv = forge.pki.privateKeyFromPem(keyPem); }
  catch (e) { return { supported: false, reason: "key", msg: "Couldn't read the private key. Paste an unencrypted RSA key (PKCS#1 or PKCS#8)." }; }
  if (!csr.publicKey || !csr.publicKey.n) return { supported: false, reason: "csr", msg: "The CSR's public key isn't RSA, so it can't be matched here." };
  try {
    const match = csr.publicKey.n.equals(priv.n) && csr.publicKey.e.equals(priv.e);
    return { supported: true, match, bits: priv.n.bitLength() };
  } catch (e) {
    return { supported: false, reason: "compare", msg: "Couldn't compare the keys." };
  }
}

export default { generate, decode, opensslCommand, keyMatch };
