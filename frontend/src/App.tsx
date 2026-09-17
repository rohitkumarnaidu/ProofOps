import { HashRouter, Link, Route, Routes } from "react-router-dom";
import { CommandCenter } from "./views/CommandCenter";
import { IncidentDetail } from "./views/IncidentDetail";
import { SafetyGate } from "./views/SafetyGate";

/** ProofOps UI shell (M19a): 3 of 5 routes live; Execution + RCA views
    land in commit B. No route renders without backend data or an honest
    empty state. */
export function App() {
  return (
    <HashRouter>
      <nav className="flex gap-4 border-b border-gray-800 px-6 py-3 text-sm">
        <Link to="/" className="font-bold text-sky-300">
          ProofOps
        </Link>
        <Link to="/" className="hover:underline">
          Command Center
        </Link>
        <Link to="/safety" className="hover:underline">
          Safety Gate
        </Link>
      </nav>
      <Routes>
        <Route path="/" element={<CommandCenter />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/safety" element={<SafetyGate />} />
      </Routes>
    </HashRouter>
  );
}
