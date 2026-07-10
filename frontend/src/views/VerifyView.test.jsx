import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { VerifyView } from "./VerifyView.jsx";
import * as api from "../lib/api.js";

vi.mock("../lib/api.js", () => ({
  verify: vi.fn(),
  sign: vi.fn()
}));
vi.mock("../lib/data.js", () => ({ copyText: vi.fn(() => Promise.resolve()) }));

function fillTextareas(values) {
  const tas = document.querySelectorAll("textarea");
  values.forEach((v, i) => { if (v != null && tas[i]) fireEvent.change(tas[i], { target: { value: v } }); });
  return tas;
}

const PUB = "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----";

describe("VerifyView — combined Sign & Verify", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders the Sign & verify header and defaults to Sign mode", () => {
    render(<VerifyView push={vi.fn()} />);
    expect(screen.getByText("Sign & verify")).toBeInTheDocument();
    expect(screen.getByText("Sign message")).toBeInTheDocument();
  });

  it("sign: errors without a private key and does not call the API", async () => {
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Sign message"));
    expect(await screen.findByText(/Paste the private key/i)).toBeInTheDocument();
    expect(api.sign).not.toHaveBeenCalled();
  });

  it("sign: produces a signature, then round-trips into verify", async () => {
    api.sign.mockResolvedValue({
      signature: "c2ln", signatureHex: "736967", publicKey: PUB,
      algorithm: "ML-DSA", keyKind: "ML-DSA", pqc: true
    });
    api.verify.mockResolvedValue({ valid: true, mode: "detached", algorithm: "ML-DSA", keyKind: "ML-DSA", pqc: true });
    render(<VerifyView push={vi.fn()} />);
    // sign mode textareas: [0]=message, [1]=private key
    fillTextareas(["hello", "-----BEGIN PRIVATE KEY-----\nKKK\n-----END PRIVATE KEY-----"]);
    fireEvent.click(screen.getByText("Sign message"));

    await waitFor(() => expect(api.sign).toHaveBeenCalledTimes(1));
    const signPayload = api.sign.mock.calls[0][0];
    expect(signPayload.message).toBe("hello");
    expect(signPayload.privateKey).toContain("PRIVATE KEY");
    expect(await screen.findByText(/Signed with ML-DSA/i)).toBeInTheDocument();

    // round-trip: verify the signature we just produced
    fireEvent.click(screen.getByText(/Verify this signature/i));
    await waitFor(() => expect(api.verify).toHaveBeenCalledTimes(1));
    const vPayload = api.verify.mock.calls[0][0];
    expect(vPayload.mode).toBe("detached");
    expect(vPayload.signature).toBe("c2ln");
    expect(vPayload.publicKey).toBe(PUB);
    expect(await screen.findByText(/Signature valid/i)).toBeInTheDocument();
  });

  it("verify: errors without a verifier", async () => {
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Verify", { selector: "button" }));           // switch mode
    fireEvent.click(screen.getByText("Verify signature", { selector: "button" })); // click action
    expect(await screen.findByText(/Paste the public key or certificate/i)).toBeInTheDocument();
    expect(api.verify).not.toHaveBeenCalled();
  });

  it("verify: calls api.verify with a detached payload and shows a valid result", async () => {
    api.verify.mockResolvedValue({ valid: true, mode: "detached", algorithm: "SHA256withECDSA", keyKind: "EC", pqc: false });
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Verify", { selector: "button" })); // to detached mode
    // detached textareas: [0]=message, [1]=signature, [2]=verifier
    fillTextareas(["hello", "c2ln", PUB]);
    fireEvent.click(screen.getByText("Verify signature", { selector: "button" }));
    await waitFor(() => expect(api.verify).toHaveBeenCalledTimes(1));
    expect(api.verify.mock.calls[0][0].mode).toBe("detached");
    expect(await screen.findByText(/Signature valid/i)).toBeInTheDocument();
    expect(screen.getByText("SHA256withECDSA")).toBeInTheDocument();
  });

  it("verify: switches to issuer mode and verifies with an issuer payload", async () => {
    api.verify.mockResolvedValue({ valid: true, mode: "issuer", algorithm: "SHA256withRSA", keyKind: "RSA", pqc: false, nameChainOk: true, timeValid: true });
    render(<VerifyView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Cert & issuer", { selector: "button" }));
    fillTextareas(["-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"]);
    fireEvent.click(screen.getByText("Verify certificate", { selector: "button" }));
    await waitFor(() => expect(api.verify).toHaveBeenCalled());
    expect(api.verify.mock.calls[0][0].mode).toBe("issuer");
    expect(await screen.findByText(/signed by that issuer/i)).toBeInTheDocument();
  });
});
