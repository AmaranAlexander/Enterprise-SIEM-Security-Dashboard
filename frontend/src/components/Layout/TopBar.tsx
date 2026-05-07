import { useLocation } from "react-router-dom";
import { useSummary } from "../../hooks/useStats";
import { fmtRelative } from "../../utils/time";

const PAGE_TITLES: Record<string, string> = {
  "/": "Security Dashboard",
  "/events": "Event Log",
  "/alerts": "Alert Management",
  "/investigation": "Forensic Investigation",
  "/rules": "Detection Rules",
};

export default function TopBar() {
  const location = useLocation();
  const { data: summary } = useSummary();
  const title = PAGE_TITLES[location.pathname] ?? "SIEM Platform";

  return (
    <header className="h-12 bg-slate-900 border-b border-slate-700 flex items-center justify-between px-4 flex-shrink-0">
      <h1 className="text-sm font-semibold text-slate-100">{title}</h1>

      <div className="flex items-center gap-4">
        {summary && (
          <>
            {summary.open_alerts > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                <span className="text-xs text-red-400 font-medium">
                  {summary.open_alerts} open alert{summary.open_alerts !== 1 ? "s" : ""}
                </span>
              </div>
            )}
            <div className="text-xs text-slate-500">
              Updated {fmtRelative(summary.generated_at)}
            </div>
          </>
        )}
        <div className="w-2 h-2 rounded-full bg-green-500" title="Backend connected" />
      </div>
    </header>
  );
}
