import axios from "axios";
import type {
  PaginatedEvents,
  PaginatedAlerts,
  Event,
  Alert,
  StatsSummary,
  TimelineBucket,
  TopSource,
  MitreCoverage,
  Rule,
  EventFilters,
  AlertFilters,
  InvestigationResult,
} from "../types";

const api = axios.create({
  baseURL: "http://localhost:8000",
  timeout: 15000,
});

const buildParams = (filters: Record<string, unknown>) => {
  const params = new URLSearchParams();
  for (const [key, val] of Object.entries(filters)) {
    if (val === undefined || val === null || val === "") continue;
    if (Array.isArray(val)) {
      val.forEach((v) => params.append(key, String(v)));
    } else {
      params.append(key, String(val));
    }
  }
  return params;
};

export const eventsApi = {
  list: (filters: EventFilters = {}): Promise<PaginatedEvents> =>
    api.get("/api/events", { params: buildParams(filters as Record<string, unknown>) }).then((r) => r.data),

  get: (id: number): Promise<Event & { related_events: Event[] }> =>
    api.get(`/api/events/${id}`).then((r) => r.data),

  exportUrl: (filters: EventFilters = {}, format: "csv" | "json" = "csv") => {
    const params = buildParams({ ...filters, format } as Record<string, unknown>);
    return `http://localhost:8000/api/events/export?${params.toString()}`;
  },
};

export const alertsApi = {
  list: (filters: AlertFilters = {}): Promise<PaginatedAlerts> =>
    api.get("/api/alerts", { params: buildParams(filters as Record<string, unknown>) }).then((r) => r.data),

  get: (id: number): Promise<Alert> =>
    api.get(`/api/alerts/${id}`).then((r) => r.data),

  updateStatus: (id: number, status: string): Promise<Alert> =>
    api.patch(`/api/alerts/${id}`, { status }).then((r) => r.data),

  getEvents: (id: number): Promise<{ events: Event[] }> =>
    api.get(`/api/alerts/${id}/events`).then((r) => r.data),
};

export const statsApi = {
  summary: (): Promise<StatsSummary> =>
    api.get("/api/stats/summary").then((r) => r.data),

  timeline: (hours = 24, bucket_minutes = 60): Promise<{ timeline: TimelineBucket[] }> =>
    api.get("/api/stats/timeline", { params: { hours, bucket_minutes } }).then((r) => r.data),

  topSources: (hours = 24, limit = 10): Promise<{ sources: TopSource[] }> =>
    api.get("/api/stats/top-sources", { params: { hours, limit } }).then((r) => r.data),

  eventTypes: (hours = 24): Promise<{ event_types: { type: string; count: number }[] }> =>
    api.get("/api/stats/event-types", { params: { hours } }).then((r) => r.data),

  mitreCoverage: (hours = 168): Promise<{ coverage: MitreCoverage[]; total_techniques: number }> =>
    api.get("/api/stats/mitre-coverage", { params: { hours } }).then((r) => r.data),

  investigateIp: (ip: string, hours = 168): Promise<InvestigationResult> =>
    api.get(`/api/stats/investigation/ip/${encodeURIComponent(ip)}`, { params: { hours } }).then((r) => r.data),

  investigateUser: (username: string, hours = 168): Promise<InvestigationResult> =>
    api.get(`/api/stats/investigation/user/${encodeURIComponent(username)}`, { params: { hours } }).then((r) => r.data),
};

export const rulesApi = {
  list: (): Promise<{ rules: Rule[]; total: number }> =>
    api.get("/api/rules").then((r) => r.data),
};

export const ingestApi = {
  triggerCorrelation: (lookback_minutes = 60) =>
    api.post("/api/ingest/correlate", null, { params: { lookback_minutes } }).then((r) => r.data),
};

export default api;
