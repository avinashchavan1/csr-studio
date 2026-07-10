import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DecodeView } from "./DecodeView.jsx";
import * as api from "../lib/api.js";
import { CSR_BARE, CSR_PEM } from "../test/fixtures.js";

vi.mock("../lib/api.js", () => ({
  decode: vi.fn(),
  lint: vi.fn(() => Promise.resolve(null)),
  quantumScan: vi.fn(() => Promise.resolve(null)),
  mode: vi.fn(() => "demo"),
  host: vi.fn(() => "localhost")
}));

const DECODED = {
  subject: { CN: "fixture.example.com", O: "", OU: "", L: "", ST: "", C: "US", email: "" },
  sans: [{ type: "DNS", value: "fixture.example.com" }],
  keyKind: "RSA", keyDetail: "2048-bit", verified: true, sigAlg: "SHA256withRSA",
  extensions: null, keySha256: null, keyPin: null
};

function typeCsr(value) {
  const ta = document.querySelector("textarea");
  fireEvent.change(ta, { target: { value } });
}

describe("DecodeView client gate", () => {
  beforeEach(() => vi.clearAllMocks());

  it("rejects empty input without calling the API", async () => {
    render(<DecodeView push={vi.fn()} />);
    fireEvent.click(screen.getByText("Decode & verify"));
    expect(await screen.findByText(/Paste a CSR first/i)).toBeInTheDocument();
    expect(api.decode).not.toHaveBeenCalled();
  });

  it("rejects obvious non-CSR garbage without calling the API", async () => {
    render(<DecodeView push={vi.fn()} />);
    typeCsr("this is not a csr !!! @@@ ###");
    fireEvent.click(screen.getByText("Decode & verify"));
    expect(await screen.findByText(/doesn't look like a CSR/i)).toBeInTheDocument();
    expect(api.decode).not.toHaveBeenCalled();
  });

  it("accepts an armored PEM and calls decode with it", async () => {
    api.decode.mockResolvedValue(DECODED);
    render(<DecodeView push={vi.fn()} />);
    typeCsr(CSR_PEM);
    fireEvent.click(screen.getByText("Decode & verify"));
    await waitFor(() => expect(api.decode).toHaveBeenCalledTimes(1));
    expect(api.decode.mock.calls[0][0]).toContain("BEGIN CERTIFICATE REQUEST");
  });

  it("accepts a bare base64 body and normalizes it into a PEM block before sending", async () => {
    api.decode.mockResolvedValue(DECODED);
    render(<DecodeView push={vi.fn()} />);
    typeCsr(CSR_BARE);
    fireEvent.click(screen.getByText("Decode & verify"));
    await waitFor(() => expect(api.decode).toHaveBeenCalledTimes(1));
    const sent = api.decode.mock.calls[0][0];
    expect(sent).toContain("-----BEGIN CERTIFICATE REQUEST-----");
    expect(sent).toContain("-----END CERTIFICATE REQUEST-----");
  });
});
