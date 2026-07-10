import { describe, it, expect } from "vitest";
import engine from "./engine.js";
import { CSR_PEM, CSR_BARE, KEY_PEM, OTHER_KEY_PEM, CERT_PEM } from "../test/fixtures.js";

describe("engine.decode — valid CSR", () => {
  it("reads subject, SANs, key and verifies self-signature (armored PEM)", () => {
    const d = engine.decode(CSR_PEM);
    expect(d.subject.CN).toBe("fixture.example.com");
    expect(d.subject.O).toBe("Fixture Inc");
    expect(d.subject.C).toBe("US");
    expect(d.keyKind).toBe("RSA");
    expect(d.verified).toBe(true);
    const sanValues = d.sans.map((s) => s.value);
    expect(sanValues).toContain("fixture.example.com");
    expect(sanValues).toContain("www.fixture.example.com");
  });

  it("decodes a bare base64 body (no PEM armor)", () => {
    const d = engine.decode(CSR_BARE);
    expect(d.subject.CN).toBe("fixture.example.com");
    expect(d.sans.map((s) => s.value)).toContain("fixture.example.com");
  });
});

describe("engine.decode — friendly errors", () => {
  it.each([
    ["-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----", /private key/i],
    ["-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----", /certificate/i],
    ["-----BEGIN PUBLIC KEY-----\nMIIabc\n-----END PUBLIC KEY-----", /public key/i],
    ["hello this is not a csr !!! @@@", /base64/i],
    ["", /nothing to decode/i]
  ])("throws a clear message for bad input %#", (input, re) => {
    expect(() => engine.decode(input)).toThrow(re);
  });
});

describe("engine.keyMatch", () => {
  it("matches a CSR with its own private key", () => {
    const r = engine.keyMatch(CSR_PEM, KEY_PEM);
    expect(r.supported).toBe(true);
    expect(r.match).toBe(true);
    expect(r.bits).toBe(2048);
  });

  it("reports a mismatch for a different key", () => {
    const r = engine.keyMatch(CSR_PEM, OTHER_KEY_PEM);
    expect(r.supported).toBe(true);
    expect(r.match).toBe(false);
  });

  it("rejects an unreadable private key gracefully", () => {
    const r = engine.keyMatch(CSR_PEM, "not a key");
    expect(r.supported).toBe(false);
    expect(r.msg).toBeTruthy();
  });
});

describe("engine.opensslCommand", () => {
  const subject = { CN: "cmd.example.com", O: "Org", C: "US" };
  it.each([
    [{ keyType: "rsa", size: "2048", hash: "SHA-256" }, ["openssl req", "-newkey rsa:2048", "-sha256"]],
    [{ keyType: "rsa", size: "4096", hash: "SHA-512" }, ["-newkey rsa:4096", "-sha512"]],
    [{ keyType: "ecdsa", size: "P-256", hash: "SHA-256" }, ["-newkey ec", "prime256v1"]],
    [{ keyType: "ecdsa", size: "P-384", hash: "SHA-384" }, ["-newkey ec", "secp384r1"]],
    [{ keyType: "ed25519" }, ["-newkey ed25519"]],
    [{ keyType: "pqc", pqcAlgo: "ML-DSA-65" }, ["-newkey ML-DSA-65"]]
  ])("builds a valid command for %o", (opts, fragments) => {
    const cmd = engine.opensslCommand({ subject, ...opts });
    for (const f of fragments) expect(cmd).toContain(f);
    expect(cmd).toContain("/CN=cmd.example.com");
  });

  it("ed25519 and pqc omit the digest flag", () => {
    expect(engine.opensslCommand({ subject, keyType: "ed25519" })).not.toMatch(/-sha\d/);
    expect(engine.opensslCommand({ subject, keyType: "pqc", pqcAlgo: "ML-DSA-65" })).not.toMatch(/-sha\d/);
  });
});

describe("fixtures sanity", () => {
  it("cert fixture is a certificate", () => {
    expect(CERT_PEM).toContain("BEGIN CERTIFICATE");
  });
});
