import { useEffect, useState } from "react";
import { probeMode, type Mode } from "../api";

/** Tier-aware backend probe with an honest loading state.
    null = still probing (never rendered as OFFLINE: initial OFFLINE is
    indistinguishable from a real outage). */
export function useMode(): Mode | null {
  const [mode, setMode] = useState<Mode | null>(null);
  useEffect(() => {
    void probeMode().then(setMode);
  }, []);
  return mode;
}
