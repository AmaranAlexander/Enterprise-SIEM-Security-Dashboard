import { useNavigate } from "react-router-dom";
import { fmtRelative } from "../../utils/time";
import SeverityBadge from "../SeverityBadge";
import type { Alert } from "../../types";

interface Props {
  alerts: Alert[];
}

const STATUS_STYLE: Record<string, string> = {
  open: "text-red-400",
  acknowledged: "text-yellow-400",
  closed: "text-green-400",
  false_positive: "text-slate-500 line-through",
};

export default function RecentAlerts({ alerts }: Props) {
  const navigate = useNavigate();

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-300">Recent Alerts</h3>
        <button onClick={() => navigate("/alerts")} className="text-xs text-blue-400 hover:text-blue-300">
          View all →
        </button>
      </div>

      {alerts.length === 0 ? (
        <p className="text-slate-500 text-xs text-center py-4">No alerts — system is quiet</p>
      ) : (
        <div className="space-y-2">
          {alerts.slice(0, 8).map((alert) => (
            <button
              key={alert.id}
              onClick={() => navigate(`/alerts?id=${alert.id}`)}
              className="w-full text-left p-2.5 rounded-md bg-slate-700/40 hover:bg-slate-700 transition-colors border border-slate-700/50"
            >
              <div className="flex items-start justify-between gap-2 mb-1">
                <span className="text-xs text-slate-200 font-medium leading-tight flex-1">{alert.title}</span>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div className="flex items-center gap-3 text-xs">
                {alert.mitre_technique && (
                  <span className="font-mono text-blue-400 bg-blue-900/30 px-1.5 py-0.5 rounded">
                    {alert.mitre_technique}
                  </span>
                )}
                <span className={STATUS_STYLE[alert.status] ?? "text-slate-400"}>{alert.status}</span>
                <span className="text-slate-500 ml-auto">
                  {fmtRelative(alert.created_at)}
                </span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
