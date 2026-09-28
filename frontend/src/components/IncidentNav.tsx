import { Link } from "react-router-dom";

/**
 * Navigation between the views that are about one incident.
 *
 * Three of the five primary views take an incident id, and two of them
 * (`Execution`, `Audit & Eval`) were navigation dead ends: nothing on the page
 * led anywhere, so an operator who opened a run from a link had to edit the URL
 * to see its evidence or its postmortem. This is one component used by all of
 * them, so the set of places an incident can be inspected from is defined once
 * and cannot drift per view.
 *
 * `agent` is included because the agent thread is the only surface that explains
 * a decision in prose, and Incident Detail could not previously reach it at all.
 */
export function IncidentNav({
  incidentId,
  current,
  state,
}: {
  incidentId: string;
  /** Which view the operator is currently on; rendered as current, not a link. */
  current: "incident" | "safety" | "execution" | "rca" | "agents";
  /** Optional run state, so the operator can see where the incident is. */
  state?: string | null;
}) {
  if (incidentId === "") return null;
  const encoded = encodeURIComponent(incidentId);
  const links: Array<[string, string, boolean]> = [
    ["Incident", `/incidents/${encoded}`, current === "incident"],
    ["Safety Gate", `/safety?incident_id=${encoded}`, current === "safety"],
    ["Execution", `/execution/${encoded}`, current === "execution"],
    ["Audit & Postmortem", `/rca/${encoded}`, current === "rca"],
    ["Agent", `/agents/${encoded}`, current === "agents"],
  ];

  return (
    <nav
      aria-label="Incident views"
      data-testid="incident-nav"
      className="flex flex-wrap items-center gap-1 text-xs"
    >
      {state !== undefined && state !== null && state !== "" && (
        <span className="mr-1 font-mono text-fg-subtle">{state}</span>
      )}
      {links.map(([label, to, active]) =>
        active ? (
          <span
            key={label}
            aria-current="page"
            aria-label={`${label}, current page`}
            className="rounded bg-surface-raised px-2 py-1 font-semibold text-fg"
          >
            {label}
          </span>
        ) : (
          <Link
            key={label}
            to={to}
            aria-label={label}
            className="rounded px-2 py-1 text-fg-muted hover:bg-surface-raised hover:text-fg hover:underline"
          >
            {label}
          </Link>
        ),
      )}
    </nav>
  );
}
