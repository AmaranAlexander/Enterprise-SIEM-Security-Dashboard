import type { MitreCoverage } from "../../types";

interface Props {
  coverage: MitreCoverage[];
}

const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "bg-red-900/60 border-red-700/50 text-red-300",
  "execution": "bg-orange-900/60 border-orange-700/50 text-orange-300",
  "persistence": "bg-yellow-900/60 border-yellow-700/50 text-yellow-300",
  "privilege-escalation": "bg-purple-900/60 border-purple-700/50 text-purple-300",
  "defense-evasion": "bg-pink-900/60 border-pink-700/50 text-pink-300",
  "credential-access": "bg-blue-900/60 border-blue-700/50 text-blue-300",
  "discovery": "bg-cyan-900/60 border-cyan-700/50 text-cyan-300",
  "lateral-movement": "bg-teal-900/60 border-teal-700/50 text-teal-300",
  "collection": "bg-green-900/60 border-green-700/50 text-green-300",
  "exfiltration": "bg-emerald-900/60 border-emerald-700/50 text-emerald-300",
};

const DEFAULT_COLOR = "bg-slate-700/60 border-slate-600/50 text-slate-300";

export default function MitreHeatmap({ coverage }: Props) {
  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 mb-3">
        MITRE ATT&CK® Coverage <span className="text-slate-500 font-normal">(7d)</span>
      </h3>
      {coverage.length === 0 ? (
        <p className="text-slate-500 text-xs text-center py-4">No technique data available</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {coverage.map((item) => {
            const colorClass = TACTIC_COLORS[item.tactic ?? ""] ?? DEFAULT_COLOR;
            return (
              <div
                key={item.technique}
                className={`border rounded px-2 py-1 text-xs cursor-default ${colorClass}`}
                title={`${item.technique} · ${item.tactic ?? "unknown"} · ${item.event_count} events${item.has_rule ? " · Has detection rule" : ""}`}
              >
                <div className="font-mono font-semibold">{item.technique}</div>
                <div className="opacity-75 truncate max-w-[100px]">{item.event_count} evt</div>
              </div>
            );
          })}
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        {Object.entries(TACTIC_COLORS).slice(0, 6).map(([tactic, cls]) => (
          <div key={tactic} className={`border rounded px-1.5 py-0.5 text-xs ${cls}`}>
            {tactic.replace("-", " ")}
          </div>
        ))}
      </div>
    </div>
  );
}
