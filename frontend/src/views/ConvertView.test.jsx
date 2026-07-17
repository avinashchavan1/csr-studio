import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ConvertView } from "./ConvertView.jsx";
import * as api from "../lib/api.js";

vi.mock("../lib/api.js", () => ({ convertKey: vi.fn() }));
vi.mock("../lib/data.js", () => ({ copyText: vi.fn(() => Promise.resolve()) }));

const RESULT = {
  inputType: "private-key", keyKind: "EC", keyDetail: "P-256", pqc: false,
  pkcs8Pem: "-----BEGIN PRIVATE KEY-----\nP8\n-----END PRIVATE KEY-----",
  traditionalPem: "-----BEGIN EC PRIVATE KEY-----\nS1\n-----END EC PRIVATE KEY-----",
  pkcs8DerBase64: "cDg=",
  publicPem: "-----BEGIN PUBLIC KEY-----\nPU\n-----END PUBLIC KEY-----",
  publicDerBase64: "cHU=",
  jwk: { kty: "EC", crv: "P-256", x: "eA", y: "eQ" },
  sshPublicKey: "ecdsa-sha2-nistp256 AAAA pqcert",
  spkiSha256: "AA:BB", spkiPin: "cGlu", sshFingerprint: "SHA256:abc"
};

describe("ConvertView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders and errors on empty input without calling the API", async () => {
    render(<ConvertView push={vi.fn()} />);
    expect(screen.getByText("Key converter")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Convert", { selector: "button" }));
    expect(await screen.findByText(/Paste a key/i)).toBeInTheDocument();
    expect(api.convertKey).not.toHaveBeenCalled();
  });

  it("converts a private key and shows every format", async () => {
    api.convertKey.mockResolvedValue(RESULT);
    render(<ConvertView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"),
      { target: { value: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----" } });
    fireEvent.click(screen.getByText("Convert", { selector: "button" }));

    await waitFor(() => expect(api.convertKey).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Private key — EC · P-256/i)).toBeInTheDocument();
    expect(screen.getByText("private key — PKCS#8")).toBeInTheDocument();
    expect(screen.getByText(/traditional \(SEC1\)/)).toBeInTheDocument();
    expect(screen.getByText("public key (SPKI)")).toBeInTheDocument();
    expect(screen.getByText("public JWK")).toBeInTheDocument();
    expect(screen.getByText("OpenSSH public key")).toBeInTheDocument();
    expect(screen.getByText("SHA256:abc")).toBeInTheDocument();
    expect(screen.getByText("Private key .der")).toBeInTheDocument();
  });

  it("PQC key: no JWK/SSH blocks, warning shown, pqc pill present", async () => {
    api.convertKey.mockResolvedValue({
      inputType: "private-key", keyKind: "ML-DSA", keyDetail: "ML-DSA-65", pqc: true,
      pkcs8Pem: "-----BEGIN PRIVATE KEY-----\nP\n-----END PRIVATE KEY-----",
      pkcs8DerBase64: "cA==", publicPem: "-----BEGIN PUBLIC KEY-----\nU\n-----END PUBLIC KEY-----",
      publicDerBase64: "dQ==", spkiSha256: "AA", spkiPin: "cGlu",
      warnings: ["JWK output isn't standardised yet for ML-DSA keys — use the PEM / DER forms."]
    });
    render(<ConvertView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "x" } });
    fireEvent.click(screen.getByText("Convert", { selector: "button" }));
    expect(await screen.findByText(/post-quantum/)).toBeInTheDocument();
    expect(screen.getByText(/isn't standardised yet/)).toBeInTheDocument();
    expect(screen.queryByText("public JWK")).toBeNull();
    expect(screen.queryByText("OpenSSH public key")).toBeNull();
  });

  it("shows the API error message on failure", async () => {
    api.convertKey.mockRejectedValue(new Error("This private key is encrypted."));
    render(<ConvertView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "enc" } });
    fireEvent.click(screen.getByText("Convert", { selector: "button" }));
    expect(await screen.findByText(/is encrypted/)).toBeInTheDocument();
  });
});
