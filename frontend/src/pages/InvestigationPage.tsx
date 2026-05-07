import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { fmtDateTime } from "../utils/time";
import { Search, Globe, User } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { useInvestigateIp, useInvestigateUser } from "../hooks/useStats";

type Mode = "ip" | "user";

function ResultPanel({ data, mode }: { data: ReturnType<typeof useInvestigateIp>["data"]; mode: Mode }) {
  if (!data) return null;

  const eventBreakdown = Object.entries(data.event_type_breakdown).sort(([, a], [, b]) => b - a);
  const sevBreakdown = Object.entries(data.severity_breakdown).sort(([, a], [, b]) => b - a);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="card text-center">
          <div className="text-2xl font-bold text-slate-100">{data.total_events.toLocaleString()}</div>
          <div className="text-xs text-slate-400 mt-1">Total Events</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-slate-100">
            {(data.associated_alerts ?? data.unique_source_ips ?? []).length}
          </div>
          <div className="text-xs text-slate-400 mt-1">{mode === "ip" ? "Linked Alerts" : "Source IPs"}</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 mb-1">First Seen</div>
          <div className="text-sm text-slate-200">
            {data.first_seen ? fmtDateTime(data.first_seen, "MMM dd HH:mm") : "—"}
          </div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 mb-1">Last Seen</div>
          <div className="text-sm text-slate-200">
            {data.last_seen ? fmtDateTime(data.last_seen, "MMM dd HH:mm") : "—"}
          </div>
        </div>
      </div>

      {(data.country || data.city) && (
        <div className="card flex items-center gap-3">
          <Globe className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-300">{[data.country, data.city].filter(Boolean).join(", ")}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Event Type Breakdown</h3>
          <div className="space-y-1.5">
            {eventBreakdown.map(([type, count]) => {
              const max = eventBreakdown[0]?.[1] ?? 1;
              return (
                <div key={type} className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400 w-40 truncate">{type.replace(/_/g, " ")}</span>
                  <div className="flex-1 bg-slate-700 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-blue-500"
                      style={{ width: `${(count / max) * 100}%` }}
                    />
                  </div>
                  <span className="text-slate-200 w-8 text-right font-medium">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Severity Distribution</h3>
          <div className="space-y-1.5">
            {sevBreakdown.map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-2 text-xs">
                <SeverityBadge severity={sev as "critical" | "high" | "medium" | "low" | "info"} />
                <span className="text-slate-200 ml-auto font-medium">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {mode === "ip" && data.associated_alerts && data.associated_alerts.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Associated Alerts</h3>
          <div className="space-y-2">
            {data.associated_alerts.map((alert) => (
              <div key={alert.id} className="flex items-center gap-3 p-2 bg-slate-700/40 rounded text-xs">
                <SeverityBadge severity={alert.severity} />
                <span className="text-slate-300 flex-1">{alert.title}</span>
                {alert.mitre_technique && (
                  <span className="font-mono text-blue-400">{alert.mitre_technique}</span>
                )}
                <span className="text-slate-500">{alert.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Recent Events</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700">
                {["Time", "Severity", "Type", "Source IP", "Message"].map((h) => (
                  <th key={h} className="text-left text-slate-500 pb-2 pr-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.recent_events.map((e) => (
                <tr key={e.id} className="border-b border-slate-700/50">
                  <td className="py-1.5 pr-3 text-slate-400 whitespace-nowrap">
                    {fmtDateTime(e.timestamp)}
                  </td>
                  <td className="py-1.5 pr-3"><SeverityBadge severity={e.severity} /></td>
                  <td className="py-1.5 pr-3 text-slate-300">{e.event_type.replace(/_/g, " ")}</td>
                  <td className="py-1.5 pr-3 font-mono text-blue-400">{e.source_ip ?? "—"}</td>
                  <td className="py-1.5 text-slate-400 max-w-xs truncate">{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function InvestigationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<Mode>("ip");
  const [inputValue, setInputValue] = useState("");
  const [queryIp, setQueryIp] = useState<string | null>(null);
  const [queryUser, setQueryUser] = useState<string | null>(null);

  const { data: ipData, isLoading: ipLoading } = useInvestigateIp(queryIp);
  const { data: userData, isLoading: userLoading } = useInvestigateUser(queryUser);

  useEffect(() => {
    const ip = searchParams.get("ip");
    const user = searchParams.get("user");
    if (ip) { setMode("ip"); setInputValue(ip); setQueryIp(ip); }
    if (user) { setMode("user"); setInputValue(user); setQueryUser(user); }
  }, []);

  const handleSearch = () => {
    if (!inputValue.trim()) return;
    if (mode === "ip") {
      setQueryIp(inputValue.trim());
      setQueryUser(null);
    } else {
      setQueryUser(inputValue.trim());
      setQueryIp(null);
    }
  };

  const isLoading = ipLoading || userLoading;
  const data = mode === "ip" ? ipData : userData;

  return (
    <div className="space-y-4">
      <div className="card">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Forensic Investigation</h2>
        <div className="flex gap-3 items-end">
          <div className="flex rounded-md overflow-hidden border border-slate-600">
            <button
              onClick={() => { setMode("ip"); setInputValue(""); setQueryIp(null); setQueryUser(null); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm transition-colors ${mode === "ip" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"}`}
            >
              <Globe className="w-3.5 h-3.5" /> IP Address
            </button>
            <button
              onClick={() => { setMode("user"); setInputValue(""); setQueryIp(null); setQueryUser(null); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm transition-colors ${mode === "user" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"}`}
            >
              <User className="w-3.5 h-3.5" /> Username
            </button>
          </div>

          <div className="flex-1 relative">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              placeholder={mode === "ip" ? "185.220.101.47" : "jsmith"}
              className="input w-full"
            />
          </div>
          <button onClick={handleSearch} className="btn-primary flex items-center gap-2">
            <Search className="w-4 h-4" /> Investigate
          </button>
        </div>

        <p className="text-xs text-slate-500 mt-2">
          Pivot from an IP address or username to see all associated events, linked alerts, and behavioral patterns.
        </p>
      </div>

      {isLoading && (
        <div className="text-center text-slate-400 py-8 animate-pulse">Investigating...</div>
      )}

      {!isLoading && data && (
        <ResultPanel data={data} mode={mode} />
      )}

      {!isLoading && !data && (queryIp || queryUser) && (
        <div className="text-center text-slate-500 py-12">No events found for this {mode}</div>
      )}
    </div>
  );
}
