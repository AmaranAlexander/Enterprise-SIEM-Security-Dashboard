import { AlertTriangle, Activity, Shield, Globe } from "lucide-react";
import type { StatsSummary } from "../../types";

interface Props {
  summary: StatsSummary;
}

const cards = [
  {
    key: "events_24h" as const,
    label: "Events (24h)",
    icon: Activity,
    color: "text-blue-400",
    bg: "bg-blue-900/20",
  },
  {
    key: "open_alerts" as const,
    label: "Open Alerts",
    icon: AlertTriangle,
    color: "text-red-400",
    bg: "bg-red-900/20",
  },
  {
    key: "critical_events_24h" as const,
    label: "Critical Events",
    icon: Shield,
    color: "text-orange-400",
    bg: "bg-orange-900/20",
  },
  {
    key: "unique_sources_24h" as const,
    label: "Unique Sources",
    icon: Globe,
    color: "text-emerald-400",
    bg: "bg-emerald-900/20",
  },
];

export default function StatsCards({ summary }: Props) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map(({ key, label, icon: Icon, color, bg }) => (
        <div key={key} className="card">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs text-slate-400 mb-1">{label}</p>
              <p className="text-2xl font-bold text-slate-100">{summary[key].toLocaleString()}</p>
            </div>
            <div className={`${bg} p-2 rounded-lg`}>
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
          </div>
          {key === "events_24h" && (
            <p className="text-xs text-slate-500 mt-2">
              {summary.events_today.toLocaleString()} today · {summary.events_7d.toLocaleString()} this week
            </p>
          )}
          {key === "open_alerts" && (
            <p className="text-xs text-slate-500 mt-2">
              {summary.critical_alerts} critical · {summary.open_alerts - summary.critical_alerts} other
            </p>
          )}
          {key === "critical_events_24h" && (
            <p className="text-xs text-slate-500 mt-2">
              {summary.high_events_24h.toLocaleString()} high severity events
            </p>
          )}
          {key === "unique_sources_24h" && (
            <p className="text-xs text-slate-500 mt-2">Unique attacking IPs in last 24h</p>
          )}
        </div>
      ))}
    </div>
  );
}
