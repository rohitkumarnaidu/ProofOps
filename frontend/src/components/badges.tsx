import type { Mode } from "../api";
import { StatusPill, type StatusTone } from "./ui";

/** Operating mode -> state tone. This mapping is the single source of truth;
    it used to be a parallel set of hand-picked Tailwind colour classes, which
    is how the same semantic state ended up with three different greens. */
const MODE_TONE: Record<Mode | "PROBING", StatusTone> = {
  LIVE: "ok",
  REPLAY: "warn",
  MOCK: "info",
  OFFLINE: "danger",
  PROBING: "neutral",
};

/** Operating-mode badge (M19.8): always visible, always truthful.
    Tier-aware via probeMode() over GET /meta: MOCK = backend reports the
    mock executor tier; LIVE = backend confirms the real docker tier (never
    claimed without tier confirmation); REPLAY = backend reports replay;
    OFFLINE = unreachable or unrecognized tier (never faked). null (still
    probing) renders a gray PROBING badge — probing is never displayed as
    OFFLINE. */
export function ModeBadge({ mode }: { mode: Mode | null }) {
  const label = mode ?? "PROBING";
  return (
    <span data-testid="mode-badge" data-mode={label} className="inline-flex">
      <StatusPill tone={MODE_TONE[label]} title={`Operating mode: ${label}`}>
        {label}
      </StatusPill>
    </span>
  );
}

const SEVERITY_TONE: Record<string, StatusTone> = {
  P1: "danger",
  P2: "warn",
  P3: "info",
  P4: "neutral",
};

export function SeverityChip({ severity }: { severity: string }) {
  return (
    <span data-testid="severity-chip" className="inline-flex">
      <StatusPill tone={SEVERITY_TONE[severity] ?? "neutral"}>
        {severity}
      </StatusPill>
    </span>
  );
}
