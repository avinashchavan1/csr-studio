import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { VerifyView } from "./VerifyView.jsx";
import * as api from "../lib/api.js";

vi.mock("../lib/api.js", () => ({
  verify: vi.fn()
}));

function fillTextareas(values) {
  const tas = document.querySelectorAll("textarea");
  values.forEach((v, i) => { if (v != null && tas[i]) fireEvent.change(tas[i], { target: { value: v } }); });
  return tas;
}

describe("VerifyView", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders with detached mode and a verify button", () => {
    render(<VerifyView push={vi.fn()} />);
    expect(screen.getByText("Verify a signature")).toBeInTheDocument();
    expect(screen.getByText("Verify signature")).toBeInTheDocument();
  });

  it("shows an error and does not call the API when the verifier is missing", async () => {
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Verify signature"));
    expect(await screen.findByText(/Paste the public key or certificate/i)).toBeInTheDocument();
    expect(api.verify).not.toHaveBeenCalled();
  });

  it("calls api.verify with a detached payload and renders a valid result", async () => {
    api.verify.mockResolvedValue({ valid: true, algorithm: "SHA256withECDSA", keyKind: "EC", pqc: false });
    render(<VerifyView push={vi.fn()} />);
    // textareas order in detached/text mode: message, signature, verifier
    fillTextareas(["hello", "c2ln", "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----"]);
    fireEvent.click(screen.getByText("Verify signature"));

    await waitFor(() => expect(api.verify).toHaveBeenCalledTimes(1));
    const payload = api.verify.mock.calls[0][0];
    expect(payload.mode).toBe("detached");
    expect(payload.messageEncoding).toBe("utf8");
    expect(payload.publicKey).toContain("PUBLIC KEY");
    expect(await screen.findByText(/Signature valid/i)).toBeInTheDocument();
    expect(screen.getByText("SHA256withECDSA")).toBeInTheDocument();
  });

  it("renders an invalid result with its reason", async () => {
    api.verify.mockResolvedValue({ valid: false, algorithm: "SHA256withRSA", keyKind: "RSA", pqc: false, reason: "does not match" });
    render(<VerifyView push={vi.fn()} />);
    fillTextareas(["hello", "c2ln", "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----"]);
    fireEvent.click(screen.getByText("Verify signature"));
    expect(await screen.findByText(/Not valid/i)).toBeInTheDocument();
    expect(screen.getByText(/does not match/i)).toBeInTheDocument();
  });

  it("shows a PQC badge for post-quantum results", async () => {
    api.verify.mockResolvedValue({ valid: true, algorithm: "ML-DSA-65", keyKind: "ML-DSA", pqc: true });
    render(<VerifyView push={vi.fn()} />);
    fillTextareas(["hello", "c2ln", "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----"]);
    fireEvent.click(screen.getByText("Verify signature"));
    expect(await screen.findByText(/post-quantum/i)).toBeInTheDocument();
  });

  it("switches to issuer mode and verifies with an issuer payload", async () => {
    api.verify.mockResolvedValue({ valid: true, algorithm: "SHA256withRSA", keyKind: "RSA", pqc: false, nameChainOk: true, timeValid: true });
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Certificate & issuer"));
    fillTextareas(["-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"]);
    fireEvent.click(screen.getByText("Verify certificate"));
    await waitFor(() => expect(api.verify).toHaveBeenCalled());
    expect(api.verify.mock.calls[0][0].mode).toBe("issuer");
    expect(await screen.findByText(/signed by that issuer/i)).toBeInTheDocument();
  });
});
