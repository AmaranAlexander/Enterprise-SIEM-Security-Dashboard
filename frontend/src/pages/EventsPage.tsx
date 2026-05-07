import { useState } from "react";
import { fmtDateTime, fmtDateTimeLong, fmtTime, fmtRelative } from "../utils/time";
import { Search, X, Download, ChevronLeft, ChevronRight, ExternalLink } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { useEvents, useEvent } from "../hooks/useEvents";
import { eventsApi } from "../api/client";
import type { EventFilters, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const EVENT_TYPES = ["failed_login", "successful_login", "port_scan", "sql_injection",
  "privilege_escalation", "lateral_movement", "data_exfiltration", "log_cleared",
  "firewall_block", "malware_detected", "ids_alert", "system_event"];

function EventDetail({ eventId, onClose }: { eventId: number; onClose: () => void }) {
  const { data: event } = useEvent(eventId);

  if (!event) return (
    <div className="card h-full flex items-center justify-center">
      <div className="text-slate-400 text-sm animate-pulse">Loading...</div>
    </div>
  );

  const rows = [
    ["Timestamp", fmtDateTimeLong(event.timestamp)],
    ["Source IP", event.source_ip ?? "—"],
    ["Dest IP", event.dest_ip ?? "—"],
    ["Ports", [event.source_port, event.dest_port].filter(Boolean).join(" → ") || "—"],
    ["Event Type", event.event_type],
    ["Log Source", event.log_source ?? "—"],
    ["Log Format", event.log_format ?? "—"],
    ["Username", event.username ?? "—"],
    ["Hostname", event.hostname ?? "—"],
    ["Country", [event.country, event.city].filter(Boolean).join(", ") || "—"],
    ["Risk Score", String(Math.round(event.risk_score))],
  ];

  return (
    <div className="card flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">#{event.id}</span>
          <SeverityBadge severity={event.severity} />
          {event.mitre_technique && (
            <span className="font-mono text-xs text-blue-400 bg-blue-900/30 px-1.5 py-0.5 rounded">
              {event.mitre_technique}
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
          <X className="w-4 h-4" />
        </button>
      </div>

      <p className="text-xs text-slate-300 bg-slate-700/40 rounded p-2 leading-relaxed">{event.message}</p>

      <div className="grid grid-cols-2 gap-1 text-xs">
        {rows.map(([label, value]) => (
          <div key={label} className="flex gap-2">
            <span className="text-slate-500 flex-shrink-0 w-20">{label}</span>
            <span className="text-slate-300 font-mono break-all">{value}</span>
          </div>
        ))}
      </div>

      {event.mitre_tactic && (
        <div className="text-xs">
          <span className="text-slate-500">Tactic: </span>
          <span className="text-slate-300 capitalize">{event.mitre_tactic.replace("-", " ")}</span>
        </div>
      )}

      {event.raw_log && (
        <div>
          <p className="text-xs text-slate-500 mb-1">Raw Log</p>
          <pre className="text-xs text-slate-400 bg-slate-900 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
            {event.raw_log}
          </pre>
        </div>
      )}

      {event.related_events && event.related_events.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 mb-1">Related Events ({event.related_events.length})</p>
          <div className="space-y-1">
            {event.related_events.slice(0, 5).map((rel) => (
              <div key={rel.id} className="flex items-center gap-2 text-xs p-1.5 bg-slate-700/40 rounded">
                <SeverityBadge severity={rel.severity} />
                <span className="text-slate-400">{rel.event_type}</span>
                <span className="text-slate-500 ml-auto">{fmtTime(rel.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function EventsPage() {
  const [filters, setFilters] = useState<EventFilters>({ page: 1, page_size: 50 });
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([]);
  const [search, setSearch] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [eventType, setEventType] = useState("");
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);

  const { data, isLoading } = useEvents(filters);

  const applyFilters = () => {
    setFilters({
      page: 1,
      page_size: 50,
      severity: selectedSeverities.length > 0 ? selectedSeverities : undefined,
      search: search || undefined,
      source_ip: sourceIp || undefined,
      event_type: eventType || undefined,
    });
  };

  const clearFilters = () => {
    setSelectedSeverities([]);
    setSearch("");
    setSourceIp("");
    setEventType("");
    setFilters({ page: 1, page_size: 50 });
  };

  const toggleSeverity = (s: Severity) => {
    setSelectedSeverities((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
    );
  };

  const changePage = (newPage: number) => {
    setFilters((f) => ({ ...f, page: newPage }));
  };

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex-1 min-w-48">
            <label className="text-xs text-slate-400 mb-1 block">Search</label>
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                placeholder="IP, user, message..."
                className="input w-full pl-7"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Source IP</label>
            <input
              type="text"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder="192.168.1.1"
              className="input w-36"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Event Type</label>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="input"
            >
              <option value="">All types</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Severity</label>
            <div className="flex gap-1">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  onClick={() => toggleSeverity(s)}
                  className={`badge-${s} cursor-pointer transition-opacity ${selectedSeverities.includes(s) ? "opacity-100 ring-1 ring-current" : "opacity-50 hover:opacity-75"}`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={applyFilters} className="btn-primary">Filter</button>
            <button onClick={clearFilters} className="btn-ghost">Clear</button>
            <a
              href={eventsApi.exportUrl(filters, "csv")}
              download="events.csv"
              className="btn-ghost flex items-center gap-1"
            >
              <Download className="w-3.5 h-3.5" />
              CSV
            </a>
          </div>
        </div>
      </div>

      <div className={`flex gap-3 ${selectedEventId ? "items-start" : ""}`}>
        {/* Table */}
        <div className="flex-1 card overflow-hidden">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">
              {data ? `${data.total.toLocaleString()} events` : "Loading..."}
            </span>
            {data && data.pages > 1 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => changePage((filters.page ?? 1) - 1)}
                  disabled={(filters.page ?? 1) <= 1}
                  className="btn-ghost p-1 disabled:opacity-40"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-xs text-slate-400">
                  {filters.page ?? 1} / {data.pages}
                </span>
                <button
                  onClick={() => changePage((filters.page ?? 1) + 1)}
                  disabled={(filters.page ?? 1) >= data.pages}
                  className="btn-ghost p-1 disabled:opacity-40"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-700">
                  {["Time", "Sev", "Type", "Source IP", "Dest IP", "MITRE", "User", "Message"].map((h) => (
                    <th key={h} className="text-left text-slate-500 uppercase tracking-wide pb-2 pr-3 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {isLoading && (
                  <tr>
                    <td colSpan={8} className="text-center py-8 text-slate-400">Loading events...</td>
                  </tr>
                )}
                {!isLoading && data?.events.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center py-8 text-slate-500">No events match your filters</td>
                  </tr>
                )}
                {data?.events.map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => setSelectedEventId(event.id === selectedEventId ? null : event.id)}
                    className={`border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors ${event.id === selectedEventId ? "bg-blue-900/20" : ""}`}
                  >
                    <td className="py-2 pr-3 text-slate-400 whitespace-nowrap">
                      {fmtDateTime(event.timestamp)}
                    </td>
                    <td className="py-2 pr-3">
                      <SeverityBadge severity={event.severity} />
                    </td>
                    <td className="py-2 pr-3 text-slate-300 whitespace-nowrap">
                      {event.event_type.replace(/_/g, " ")}
                    </td>
                    <td className="py-2 pr-3">
                      {event.source_ip ? (
                        <span className="font-mono text-blue-400">{event.source_ip}</span>
                      ) : "—"}
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-400">
                      {event.dest_ip ?? "—"}
                    </td>
                    <td className="py-2 pr-3">
                      {event.mitre_technique ? (
                        <span className="font-mono text-blue-400 text-xs">{event.mitre_technique}</span>
                      ) : "—"}
                    </td>
                    <td className="py-2 pr-3 text-slate-400">{event.username ?? "—"}</td>
                    <td className="py-2 text-slate-400 max-w-xs truncate">{event.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail Panel */}
        {selectedEventId && (
          <div className="w-80 flex-shrink-0">
            <EventDetail eventId={selectedEventId} onClose={() => setSelectedEventId(null)} />
          </div>
        )}
      </div>
    </div>
  );
}
