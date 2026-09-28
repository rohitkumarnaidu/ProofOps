import { useEffect, useState } from "react";
import { apiBase, auditApi, probeModeDetailed, type Mode, type ModeProbe } from "../api";
import { subscribeStream } from "../sse";

/**
 * Tier-aware backend mode, with the reason when it could not be determined.
 *
 * `null` means still probing and is never rendered as OFFLINE, because an
 * initial OFFLINE is indistinguishable from a real outage.
 *
 * `probe` carries WHY the probe failed, so the badge can say "the backend
 * rejected the request" rather than asserting the executor is absent. The
 * previous version collapsed a 401, a 500 and a dead socket into one red
 * OFFLINE pill, which is three different problems presented identically.
 *
 * When an incident id is given, the hook also subscribes to the control-plane
 * stream as a REFRESH TRIGGER only: an SSE "live" frame is not docker-tier
 * proof, and a transport close must never overwrite a probed tier without a
 * re-probe. Id-less callers (global views) use the probe alone, because the
 * control-plane stream is per-incident and no global mode stream is invented.
 */
export interface ModeState {
  mode: Mode | null;
  /** "" when the probe succeeded. */
  reason: string;
}

/** The "not probed yet" value, typed so it cannot be mistaken for a Mode. */
const PROBING: ModeProbe = { mode: null, reason: "", failure: null };

export function useModeState(incidentId?: string): ModeState {
  const [probe, setProbe] = useState<ModeProbe>(PROBING);

  useEffect(() => {
    let cancelled = false;
    function refresh(): void {
      // probeModeDetailed never rejects, so there is no unhandled rejection
      // here; the previous `.then()` with no catch depended on an internal
      // try/catch in another file staying in place.
      void probeModeDetailed().then((next) => {
        if (cancelled) return;
        setProbe({
          mode: next.mode,
          reason: next.failure === null ? "" : next.reason,
          failure: next.failure,
        });
      });
    }
    refresh();
    if (incidentId === undefined || incidentId === "") {
      return () => {
        cancelled = true;
      };
    }
    const stream = `${apiBase()}/stream/incidents/${encodeURIComponent(incidentId)}`;
    const pollUrl = auditApi.pollUrl(incidentId);
    const unsubscribe = subscribeStream(stream, pollUrl, null, {
      onItem: refresh,
      onMode: refresh,
    });
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [incidentId]);

  return { mode: probe.mode, reason: probe.reason };
}

/** Just the mode, for the common case. */
export function useMode(incidentId?: string): Mode | null {
  return useModeState(incidentId).mode;
}
