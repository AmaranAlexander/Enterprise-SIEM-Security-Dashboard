import { useState } from "react";
import { fmtDateTime, fmtRelative } from "../utils/time";
import { ChevronDown, ChevronUp, Users, Globe, Activity, X } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { useAlerts, useAlertEvents, useUpdateAlertStatus } from "../hooks/useAlerts";
import type { Alert, AlertStatus } from "../types";

const STATUS_OPTIONS: AlertStatus[] = ["open", "acknowledged", "closed", "false_positive"];
const STATUS_LABELS: Record<AlertStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  closed: "Closed",
  false_positive: "False Positive",
};
const STATUS_COLORS: Record<AlertStatus, string> = {
  open: "text-red-400 bg-red-900/20 border-red-700/50",
  acknowledged: "text-yellow-400 bg-yellow-900/20 border-yellow-700/50",
  closed: "text-green-400 bg-green-900/20 border-green-700/50",
  false_positive: "text-slate-400 bg-slate-700/20 border-slate-600/50",
};

function AlertCard({ alert }: { alert: Alert }) {
  const [expanded, setExpanded] = useState(false);
  const { data: eventsData } = useAlertEvents(expanded ? alert.id : null);
  const { mutate: updateStatus } = useUpdateAlertStatus();

  return (
    <div className={`card border-l-2 ${alert.severity === "critical" ? "border-l-red-500" : alert.severity === "high" ? "border-l-orange-500" : alert.severity === "medium" ? "border-l-yellow-500" : "border-l-blue-500"}`}>
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <SeverityBadge severity={alert.severity} />
            {alert.mitre_technique && (
              <span className="font-mono text-xs text-blue-400 bg-blue-900/30 px-1.5 py-0.5 rounded border border-blue-800/50">
                {alert.mitre_technique}
              </span>
            )}
            {alert.mitre_tactic && (
              <span className="text-xs text-slate-400 capitalize">{alert.mitre_tactic.replace("-", " ")}</span>
            )}
            <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[alert.status]}`}>
              {STATUS_LABELS[alert.status]}
            </span>
          </div>

          <h3 className="text-sm font-medium text-slate-100 mb-1">{alert.title}</h3>
          <p className="text-xs text-slate-400 line-clamp-2">{alert.description}</p>

          <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
            <span className="flex items-center gap-1">
              <Activity className="w-3 h-3" />
              {alert.event_count} events
            </span>
            {alert.source_ips.length > 0 && (
              <span className="flex items-center gap-1">
                <Globe className="w-3 h-3" />
                {alert.source_ips.slice(0, 2).join(", ")}
                {alert.source_ips.length > 2 && ` +${alert.source_ips.length - 2}`}
              </span>
            )}
            {alert.affected_users.length > 0 && (
              <span className="flex items-center gap-1">
                <Users className="w-3 h-3" />
                {alert.affected_users.slice(0, 2).join(", ")}
              </span>
            )}
            <span className="ml-auto">
              {fmtRelative(alert.created_at)}
            </span>
          </div>
        </div>

        <div className="flex flex-col items-end gap-2 flex-shrink-0">
          <div className="text-right">
            <div className="text-lg font-bold text-slate-200">{Math.round(alert.risk_score)}</div>
            <div className="text-xs text-slate-500">risk</div>
          </div>
          <button
            onClick={() => setExpanded((e) => !e)}
            className="btn-ghost p-1"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-slate-700 space-y-3">
          <div className="flex flex-wrap gap-2">
            <span className="text-xs text-slate-500">Update status:</span>
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => updateStatus({ id: alert.id, status: s })}
                disabled={alert.status === s}
                className={`text-xs px-2 py-0.5 rounded border transition-colors disabled:opacity-40 ${STATUS_COLORS[s]}`}
              >
                {STATUS_LABELS[s]}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <div className="text-slate-500 mb-1">First Seen</div>
              <div className="text-slate-300">{fmtDateTime(alert.first_seen)}</div>
            </div>
            <div>
              <div className="text-slate-500 mb-1">Last Seen</div>
              <div className="text-slate-300">{fmtDateTime(alert.last_seen)}</div>
            </div>
            <div>
              <div className="text-slate-500 mb-1">Rule ID</div>
              <div className="text-slate-300 font-mono">{alert.rule_id}</div>
            </div>
          </div>

          {eventsData && eventsData.events.length > 0 && (
            <div>
              <div className="text-xs text-slate-500 mb-2">Linked Events ({eventsData.events.length})</div>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {eventsData.events.map((e) => (
                  <div key={e.id} className="flex items-center gap-2 text-xs p-2 bg-slate-700/40 rounded">
                    <SeverityBadge severity={e.severity} />
                    <span className="font-mono text-blue-400">{e.source_ip ?? "—"}</span>
                    <span className="text-slate-400">{e.event_type.replace(/_/g, " ")}</span>
                    <span className="text-slate-500 ml-auto">{fmtDateTime(e.timestamp)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<string[]>(["open", "acknowledged"]);
  const { data, isLoading } = useAlerts({ status: statusFilter, page: 1, page_size: 100 });

  const toggleStatus = (s: string) =>
    setStatusFilter((prev) => prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]);

  const bySeverity = {
    critical: data?.alerts.filter((a) => a.severity === "critical") ?? [],
    high: data?.alerts.filter((a) => a.severity === "high") ?? [],
    medium: data?.alerts.filter((a) => a.severity === "medium") ?? [],
    low: data?.alerts.filter((a) => a.severity === "low") ?? [],
  };

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex items-center gap-4">
          <span className="text-sm text-slate-400">Filter by status:</span>
          <div className="flex gap-2">
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => toggleStatus(s)}
                className={`text-xs px-3 py-1 rounded-md border transition-colors ${
                  statusFilter.includes(s) ? STATUS_COLORS[s] : "text-slate-500 border-slate-700 hover:border-slate-600"
                }`}
              >
                {STATUS_LABELS[s]}
              </button>
            ))}
          </div>
          <span className="ml-auto text-xs text-slate-500">
            {data ? `${data.total} alerts` : "Loading..."}
          </span>
        </div>
      </div>

      {isLoading && (
        <div className="text-center text-slate-400 py-8 animate-pulse">Loading alerts...</div>
      )}

      {!isLoading && data?.total === 0 && (
        <div className="text-center text-slate-500 py-12">
          <div className="text-3xl mb-2">✓</div>
          <div className="text-sm">No alerts match the current filters</div>
        </div>
      )}

      {(["critical", "high", "medium", "low"] as const).map((sev) => {
        const alerts = bySeverity[sev];
        if (alerts.length === 0) return null;
        return (
          <div key={sev}>
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={sev} />
              <span className="text-xs text-slate-500">{alerts.length} alert{alerts.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="space-y-2">
              {alerts.map((a) => <AlertCard key={a.id} alert={a} />)}
            </div>
          </div>
        );
      })}
    </div>
  );
}
