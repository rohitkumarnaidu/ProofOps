import { HashRouter, Link, Route, Routes } from "react-router-dom";
import { CommandCenter } from "./views/CommandCenter";
import { ExecutionView } from "./views/ExecutionView";
import { IncidentDetail } from "./views/IncidentDetail";
import { RCAView } from "./views/RCAView";
import { SafetyGate } from "./views/SafetyGate";

/** ProofOps UI shell (M19b): all 5 MVP routes live. Every route renders
    backend data or an honest empty/error state — no route fakes content. */
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
        <Link to="/rca/inc-1" className="hover:underline">
          RCA
        </Link>
      </nav>
      <Routes>
        <Route path="/" element={<CommandCenter />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/safety" element={<SafetyGate />} />
        <Route path="/execution/:id" element={<ExecutionView />} />
        <Route path="/rca/:id" element={<RCAView />} />
      </Routes>
    </HashRouter>
  );
}
