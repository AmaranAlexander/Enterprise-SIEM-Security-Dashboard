import type { Severity } from "../types";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge-${severity}`}>{LABELS[severity] ?? severity}</span>;
}
