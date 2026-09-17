/** State-diff renderer (M19.9): BEFORE/AFTER per changed key.
    Renders the sandbox Execution.state_diff shape
    {before, after, changed: {key: {before, after}}} verbatim — no
    invented rows. Empty diff = honest "no changes" state. */
export interface StateDiffShape {
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  changed?: Record<string, { before: unknown; after: unknown }>;
}

function fmt(value: unknown): string {
  if (value === null || value === undefined) return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

export function StateDiff({ diff }: { diff: StateDiffShape | null }) {
  if (diff === null || diff.changed === undefined) {
    return (
      <p data-testid="diff-empty" className="text-sm text-gray-400">
        No state diff recorded yet — executions appear here once the control
        plane runs them.
      </p>
    );
  }
  const keys = Object.keys(diff.changed);
  if (keys.length === 0) {
    return (
      <p data-testid="diff-zero" className="text-sm text-gray-400">
        Zero diff — the action changed nothing (blocked reads look like this).
      </p>
    );
  }
  return (
    <table data-testid="diff-table" className="w-full text-sm">
      <thead>
        <tr className="text-left text-gray-400">
          <th className="py-1">Key</th>
          <th>Before</th>
          <th>After</th>
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => (
          <tr key={key} className="border-t border-gray-800">
            <td className="py-1 font-mono">{key}</td>
            <td className="font-mono text-red-300">
              {fmt(diff.changed?.[key]?.before)}
            </td>
            <td className="font-mono text-green-300">
              {fmt(diff.changed?.[key]?.after)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
