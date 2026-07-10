import { describe, it, expect, beforeEach } from "vitest";
import * as api from "./api.js";

describe("api config", () => {
  beforeEach(() => api.setConfig({}));

  it("forces baseUrl to the hardcoded default (not user-editable)", () => {
    const c = api.setConfig({ baseUrl: "https://evil.example.com/api" });
    expect(c.baseUrl).not.toBe("https://evil.example.com/api");
    expect(c.baseUrl).toContain("/api");
  });

  it("is connected (baseUrl present) with a resolvable host", () => {
    expect(api.mode()).toBe("connected");
    expect(api.host()).toBeTruthy();
  });

  it.each([
    [-5, 0],
    [0, 0],
    [3, 3],
    [5, 5],
    [99, 5]
  ])("clamps retries %s -> %s", (input, expected) => {
    expect(api.setConfig({ retries: input }).retries).toBe(expected);
  });

  it.each([
    [100, 2000],
    [2000, 2000],
    [30000, 30000],
    [999999, 180000]
  ])("clamps timeoutMs %s -> %s", (input, expected) => {
    expect(api.setConfig({ timeoutMs: input }).timeoutMs).toBe(expected);
  });

  it.each([
    [0, 200],
    [200, 200],
    [1400, 1400],
    [99999, 8000]
  ])("clamps demoLatencyMs %s -> %s", (input, expected) => {
    expect(api.setConfig({ demoLatencyMs: input }).demoLatencyMs).toBe(expected);
  });

  it.each([
    ["cookie", "cookie"],
    ["bearer", "bearer"],
    ["none", "none"],
    ["bogus", "none"],
    ["", "none"]
  ])("normalizes authMode %s -> %s", (input, expected) => {
    expect(api.setConfig({ authMode: input }).authMode).toBe(expected);
  });

  it("trims the bearer token", () => {
    expect(api.setConfig({ token: "  abc123  " }).token).toBe("abc123");
  });

  it("getConfig returns a copy (not a live reference)", () => {
    const a = api.getConfig();
    a.retries = 999;
    expect(api.getConfig().retries).not.toBe(999);
  });
});
