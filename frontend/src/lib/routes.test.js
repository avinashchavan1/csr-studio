import { describe, it, expect } from "vitest";
import { pathToView, recordIdFromPath, viewToPath } from "./routes.js";

describe("pathToView", () => {
  it.each([
    ["/", "generate"],
    ["", "generate"],
    ["/decode", "decode"],
    ["/decode/", "decode"],
    ["/verify", "verify"],
    ["/quantum", "quantum"],
    ["/compare", "compare"],
    ["/history", "history"],
    ["/server", "server"],
    ["/server/", "server"],
    ["/nope", "notfound"],
    ["/foo/bar", "notfound"],
    ["/decode/extra", "notfound"],
    ["/r/abc123", "record"],
    ["/r/abc123/", "record"]
  ])("%s -> %s", (path, view) => {
    expect(pathToView(path)).toBe(view);
  });
});

describe("recordIdFromPath", () => {
  it.each([
    ["/r/abc-123", "abc-123"],
    ["/r/abc/", "abc"],
    ["/r/a%20b", "a b"],
    ["/r/9dda98e0-7e4c", "9dda98e0-7e4c"],
    ["/decode", null],
    ["/", null],
    ["/r/", null],
    ["/r/a/b", null]
  ])("%s -> %s", (path, id) => {
    expect(recordIdFromPath(path)).toBe(id);
  });
});

describe("viewToPath", () => {
  it.each([
    ["generate", "/"],
    ["decode", "/decode"],
    ["verify", "/verify"],
    ["quantum", "/quantum"],
    ["compare", "/compare"],
    ["history", "/history"],
    ["server", "/server"],
    ["record", "/"],
    ["notfound", "/"],
    ["bogus", "/"]
  ])("%s -> %s", (view, path) => {
    expect(viewToPath(view)).toBe(path);
  });
});

describe("round-trip: known views survive viewToPath -> pathToView", () => {
  it.each(["decode", "verify", "quantum", "compare", "history", "server"])("%s", (view) => {
    expect(pathToView(viewToPath(view))).toBe(view);
  });
  it("generate maps to /", () => {
    expect(pathToView(viewToPath("generate"))).toBe("generate");
  });
});
