import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ChainView } from "./ChainView.jsx";
import * as api from "../lib/api.js";

vi.mock("../lib/api.js", () => ({ chain: vi.fn() }));
vi.mock("../lib/data.js", () => ({ copyText: vi.fn(() => Promise.resolve()) }));

const CERT = (over) => ({
  index: 0, subject: "CN=leaf.example.com", issuer: "CN=Test Intermediate",
  serialHex: "1a2b", notBefore: "2026-01-01 00:00 UTC", notAfter: "2027-01-01 00:00 UTC",
  expired: false, notYetValid: false, selfSigned: false, ca: false,
  keyKind: "EC", keyDetail: "P-256", pqc: false, signatureAlgorithm: "SHA256WITHECDSA",
  sha256: "AA:BB", ...over
});

const GOOD = {
  chain: [
    CERT({}),
    CERT({ index: 1, subject: "CN=Test Intermediate", issuer: "CN=Test Root", ca: true }),
    CERT({ index: 2, subject: "CN=Test Root", issuer: "CN=Test Root", ca: true, selfSigned: true })
  ],
  links: [
    { childIndex: 0, parentIndex: 1, signatureValid: true, issuerIsCa: true, issuerCanSignCerts: true, nameChainOk: true },
    { childIndex: 1, parentIndex: 2, signatureValid: true, issuerIsCa: true, issuerCanSignCerts: true, nameChainOk: true }
  ],
  complete: true, allValid: true,
  orderedPem: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
};

describe("ChainView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders and errors on empty input without calling the API", async () => {
    render(<ChainView push={vi.fn()} />);
    expect(screen.getByText(/Chain builder/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));
    expect(await screen.findByText(/Paste one or more/i)).toBeInTheDocument();
    expect(api.chain).not.toHaveBeenCalled();
  });

  it("valid chain: ordered cards, roles, link checks, corrected PEM", async () => {
    api.chain.mockResolvedValue(GOOD);
    render(<ChainView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"),
      { target: { value: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----" } });
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));

    await waitFor(() => expect(api.chain).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Chain complete and valid/)).toBeInTheDocument();
    expect(screen.getByText("Leaf")).toBeInTheDocument();
    expect(screen.getByText("Intermediate")).toBeInTheDocument();
    expect(screen.getByText("Root")).toBeInTheDocument();
    expect(screen.getByText("CN=leaf.example.com")).toBeInTheDocument();
    expect(screen.getAllByText("signature")).toHaveLength(2);
    expect(screen.getByText(/corrected chain/)).toBeInTheDocument();
  });

  it("incomplete chain: shows the missing issuer + AIA URL", async () => {
    api.chain.mockResolvedValue({
      chain: [CERT({})], links: [], complete: false, allValid: false,
      missingIssuer: "CN=Test Intermediate",
      missingIssuerUrl: "http://ca.example.com/int.crt",
      warnings: ["The chain is incomplete — missing the issuer \"CN=Test Intermediate\"."],
      orderedPem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n"
    });
    render(<ChainView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "cert" } });
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));
    expect(await screen.findByText(/missing an issuer/)).toBeInTheDocument();
    expect(screen.getByText("http://ca.example.com/int.crt")).toBeInTheDocument();
  });

  it("bad link: failure pills render", async () => {
    api.chain.mockResolvedValue({
      ...GOOD, allValid: false,
      links: [
        { childIndex: 0, parentIndex: 1, signatureValid: false, issuerIsCa: false, issuerCanSignCerts: true, nameChainOk: true },
        GOOD.links[1]
      ]
    });
    render(<ChainView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "cert" } });
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));
    expect(await screen.findByText(/complete but has problems/)).toBeInTheDocument();
    expect(screen.getByText("signature fails")).toBeInTheDocument();
    expect(screen.getByText("issuer not a CA")).toBeInTheDocument();
  });

  it("extras section lists certs outside the chain", async () => {
    api.chain.mockResolvedValue({
      ...GOOD,
      extras: [CERT({ subject: "CN=stranger.example.org" })],
      warnings: ["1 pasted certificate(s) aren't part of this chain."]
    });
    render(<ChainView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "cert" } });
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));
    expect(await screen.findByText("Not part of this chain")).toBeInTheDocument();
    expect(screen.getByText("CN=stranger.example.org")).toBeInTheDocument();
  });

  it("shows the API error message on failure", async () => {
    api.chain.mockRejectedValue(new Error("never paste private keys here"));
    render(<ChainView push={vi.fn()} />);
    fireEvent.change(document.querySelector("textarea"), { target: { value: "key" } });
    fireEvent.click(screen.getByText(/Build & validate chain/, { selector: "button" }));
    expect(await screen.findByText(/never paste private keys/)).toBeInTheDocument();
  });
});
