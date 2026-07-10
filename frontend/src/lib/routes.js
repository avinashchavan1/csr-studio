/* Pure URL <-> view routing (no globals) so it can be unit-tested. */
export const VIEW_PATH = {
  generate: "/", decode: "/decode", verify: "/verify", quantum: "/quantum",
  compare: "/compare", history: "/history", server: "/server"
};
export const PATH_VIEW = {
  "/decode": "decode", "/verify": "verify", "/quantum": "quantum",
  "/compare": "compare", "/history": "history", "/server": "server"
};

/** /r/<id> permalink → the record id, else null. */
export function recordIdFromPath(pathname) {
  const m = (pathname || "").match(/^\/r\/([^/]+)\/?$/);
  return m ? decodeURIComponent(m[1]) : null;
}

/** Map a pathname to a view id. Unknown paths → "notfound". */
export function pathToView(pathname) {
  const p = (pathname || "/").replace(/\/+$/, "") || "/";
  if (p === "/") return "generate";
  if (recordIdFromPath(pathname)) return "record";
  return PATH_VIEW[p] || "notfound";
}

/** View id → its canonical path. */
export function viewToPath(view) {
  return VIEW_PATH[view] || "/";
}
