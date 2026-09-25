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
        No state diff was returned by the available API. This view does not
        invent one.
      </p>
    );
  }
  const keys = Object.keys(diff.changed);
  if (keys.length === 0) {
    return (
      <p data-testid="diff-zero" className="text-sm text-gray-400">
        Zero diff — the action changed nothing.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table data-testid="diff-table" className="w-full text-sm">
        <caption className="sr-only">Execution state changes</caption>
        <thead>
          <tr className="text-left text-gray-400">
            <th scope="col" className="py-1">
              Key
            </th>
            <th scope="col">Before</th>
            <th scope="col">After</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((key) => (
            <tr key={key} className="border-t border-gray-800">
              <td className="max-w-64 break-all py-1 font-mono">{key}</td>
              <td className="max-w-80 break-all font-mono text-red-300">
                {fmt(diff.changed?.[key]?.before)}
              </td>
              <td className="max-w-80 break-all font-mono text-green-300">
                {fmt(diff.changed?.[key]?.after)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
