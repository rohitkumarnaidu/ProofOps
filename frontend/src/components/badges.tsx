import type { Mode } from "../api";

const COLORS: Record<Mode | "PROBING", string> = {
  LIVE: "bg-green-900 text-green-200 border-green-700",
  REPLAY: "bg-amber-900 text-amber-200 border-amber-700",
  MOCK: "bg-sky-900 text-sky-200 border-sky-700",
  OFFLINE: "bg-red-900 text-red-200 border-red-700",
  PROBING: "bg-gray-800 text-gray-300 border-gray-600",
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
    <span
      data-testid="mode-badge"
      data-mode={label}
      className={`inline-block rounded border px-2 py-0.5 text-xs font-bold tracking-widest ${COLORS[label]}`}
    >
      {label}
    </span>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  P1: "bg-red-800 text-white",
  P2: "bg-orange-700 text-white",
  P3: "bg-yellow-700 text-black",
  P4: "bg-gray-600 text-white",
};

export function SeverityChip({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? "bg-gray-700 text-white";
  return (
    <span
      data-testid="severity-chip"
      className={`inline-block rounded px-2 py-0.5 text-xs font-bold ${color}`}
    >
      {severity}
    </span>
  );
}
