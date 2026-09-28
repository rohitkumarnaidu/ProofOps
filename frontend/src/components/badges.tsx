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
    OFFLINE = the tier could not be read. null (still probing) renders a gray
    PROBING badge — probing is never displayed as OFFLINE.

    `reason` is the probe's explanation when it failed. Without it the badge
    asserted "OFFLINE" for a 401, a 500 and a dead socket alike, which are
    three different problems an operator resolves in three different ways. */
export function ModeBadge({
  mode,
  reason = "",
}: {
  mode: Mode | null;
  reason?: string;
}) {
  const label = mode ?? "PROBING";
  const title =
    reason === ""
      ? `Operating mode: ${label}`
      : `Operating mode: ${label} — ${reason}`;
  return (
    <span data-testid="mode-badge" data-mode={label} className="inline-flex">
      <StatusPill tone={MODE_TONE[label]} title={title}>
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
