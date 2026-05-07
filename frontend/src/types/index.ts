export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "acknowledged" | "closed" | "false_positive";

export interface Event {
  id: number;
  timestamp: string;
  source_ip: string | null;
  dest_ip: string | null;
  source_port: number | null;
  dest_port: number | null;
  event_type: string;
  severity: Severity;
  message: string;
  raw_log: string | null;
  log_source: string | null;
  log_format: string | null;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  risk_score: number;
  username: string | null;
  hostname: string | null;
  country: string | null;
  city: string | null;
  extra_fields: Record<string, unknown>;
  related_events?: Event[];
}

export interface Alert {
  id: number;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  risk_score: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  source_ips: string[];
  affected_users: string[];
  event_ids: number[];
}

export interface StatsSummary {
  total_events: number;
  events_today: number;
  events_24h: number;
  events_7d: number;
  open_alerts: number;
  critical_alerts: number;
  critical_events_24h: number;
  high_events_24h: number;
  unique_sources_24h: number;
  severity_breakdown: Record<Severity, number>;
  generated_at: string;
}

export interface TimelineBucket {
  time: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface TopSource {
  source_ip: string;
  country: string | null;
  event_count: number;
  avg_risk_score: number;
  max_risk_score: number;
}

export interface MitreCoverage {
  technique: string;
  tactic: string | null;
  event_count: number;
  has_rule: boolean;
  rule_name: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  severity: Severity;
  risk_score: number;
  total_alerts: number;
  open_alerts: number;
  conditions: RuleCondition[];
  condition_summary: string[];
}

export interface RuleCondition {
  event_type: string;
  min_count?: number;
  window_minutes?: number;
  group_by?: string;
  distinct_dest_min?: number;
  requires_same?: string;
}

export interface PaginatedEvents {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  events: Event[];
}

export interface PaginatedAlerts {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  alerts: Alert[];
}

export interface EventFilters {
  start_time?: string;
  end_time?: string;
  severity?: string[];
  source_ip?: string;
  event_type?: string;
  mitre_technique?: string;
  search?: string;
  log_source?: string;
  page?: number;
  page_size?: number;
}

export interface AlertFilters {
  status?: string[];
  severity?: string[];
  rule_id?: string;
  page?: number;
  page_size?: number;
}

export interface InvestigationResult {
  ip_address?: string;
  username?: string;
  country: string | null;
  city: string | null;
  total_events: number;
  event_type_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  first_seen: string | null;
  last_seen: string | null;
  associated_alerts?: Alert[];
  unique_source_ips?: string[];
  recent_events: Event[];
}
