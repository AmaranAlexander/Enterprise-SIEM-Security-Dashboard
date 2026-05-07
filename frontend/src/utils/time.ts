import { format, formatDistanceToNow } from "date-fns";

// Backend stores timestamps as naive UTC strings without a 'Z' suffix.
// Appending 'Z' makes JavaScript treat them as UTC before converting to local time.
function toLocal(ts: string): Date {
  return new Date(ts.endsWith("Z") || ts.includes("+") ? ts : ts + "Z");
}

export function fmtDateTime(ts: string, fmt = "MM-dd HH:mm"): string {
  return format(toLocal(ts), fmt);
}

export function fmtDateTimeLong(ts: string): string {
  return format(toLocal(ts), "yyyy-MM-dd HH:mm:ss");
}

export function fmtTime(ts: string): string {
  return format(toLocal(ts), "HH:mm:ss");
}

export function fmtRelative(ts: string): string {
  return formatDistanceToNow(toLocal(ts), { addSuffix: true });
}

export function fmtChartTime(ts: string): string {
  return format(toLocal(ts), "HH:mm");
}
