import { useEffect, useState } from "react";
import { apiBase, probeMode, type Mode } from "../api";
import { subscribeStream } from "../sse";

/** Tier-aware backend mode with an honest loading state plus live refresh.
    null = still probing (never rendered as OFFLINE: initial OFFLINE is
    indistinguishable from a real outage). Every displayed mode comes from
    probeMode() over GET /meta (tier truth, fail-closed to OFFLINE), which
    stays the initial fetch and the fallback. When an incident id is given,
    the hook also subscribes to the control-plane stream
    (/stream/incidents/{id} per API.md): stream traffic is a refresh trigger
    only — onItem/onMode callbacks re-probe the tier instead of displaying
    transport health as the tier (an SSE LIVE is not docker-tier proof, and
    a transport OFFLINE never overwrites a probed tier without a re-probe).
    Id-less callers (global views) use probeMode only: the control-plane
    stream is per-incident, and no global mode stream is invented here. */
export function useMode(incidentId?: string): Mode | null {
  const [mode, setMode] = useState<Mode | null>(null);
  useEffect(() => {
    let cancelled = false;
    function refresh(): void {
      void probeMode().then((m) => {
        if (!cancelled) setMode(m);
      });
    }
    refresh();
    if (incidentId === undefined || incidentId === "") {
      return () => {
        cancelled = true;
      };
    }
    const stream = `${apiBase()}/stream/incidents/${encodeURIComponent(incidentId)}`;
    const unsubscribe = subscribeStream(stream, stream, null, {
      onItem: refresh,
      onMode: refresh,
    });
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [incidentId]);
  return mode;
}
