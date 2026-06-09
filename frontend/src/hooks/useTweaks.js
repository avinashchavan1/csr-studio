import { useState, useCallback } from "react";

const TKEY = "csrgen.tweaks.v1";

export function useTweaks(defaults) {
  const [tweaks, setTweaks] = useState(() => {
    try { return { ...defaults, ...JSON.parse(localStorage.getItem(TKEY) || "{}") }; }
    catch (e) { return { ...defaults }; }
  });

  const setTweak = useCallback((keyOrObj, value) => {
    setTweaks(prev => {
      const next = typeof keyOrObj === "object" ? { ...prev, ...keyOrObj } : { ...prev, [keyOrObj]: value };
      try { localStorage.setItem(TKEY, JSON.stringify(next)); } catch (e) {}
      return next;
    });
  }, []);

  return [tweaks, setTweak];
}
