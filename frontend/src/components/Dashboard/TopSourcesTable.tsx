import { useNavigate } from "react-router-dom";
import type { TopSource } from "../../types";

interface Props {
  sources: TopSource[];
}

const getRiskColor = (score: number) => {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-blue-400";
};

const RiskBar = ({ score }: { score: number }) => (
  <div className="flex items-center gap-2">
    <div className="flex-1 bg-slate-700 rounded-full h-1.5 max-w-16">
      <div
        className={`h-1.5 rounded-full ${score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-yellow-500" : "bg-blue-500"}`}
        style={{ width: `${Math.min(100, score)}%` }}
      />
    </div>
    <span className={`text-xs font-medium ${getRiskColor(score)}`}>{Math.round(score)}</span>
  </div>
);

export default function TopSourcesTable({ sources }: Props) {
  const navigate = useNavigate();

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 mb-3">Top Source IPs (24h)</h3>
      <div className="space-y-0.5">
        <div className="grid grid-cols-[1fr_auto_auto] gap-2 px-2 pb-1 text-xs text-slate-500 uppercase tracking-wide">
          <span>IP / Country</span>
          <span className="text-right">Events</span>
          <span className="text-right pr-1">Risk</span>
        </div>
        {sources.length === 0 && (
          <p className="text-slate-500 text-xs text-center py-4">No events in this period</p>
        )}
        {sources.map((src) => (
          <button
            key={src.source_ip}
            onClick={() => navigate(`/investigation?ip=${src.source_ip}`)}
            className="w-full grid grid-cols-[1fr_auto_auto] gap-2 px-2 py-2 rounded-md hover:bg-slate-700/50 text-left transition-colors"
          >
            <div>
              <div className="text-xs font-mono text-blue-300 hover:underline">{src.source_ip}</div>
              <div className="text-xs text-slate-500">{src.country ?? "Unknown"}</div>
            </div>
            <div className="text-right">
              <span className="text-xs text-slate-200 font-medium">{src.event_count.toLocaleString()}</span>
            </div>
            <div className="min-w-[80px]">
              <RiskBar score={src.max_risk_score} />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
