import StatsCards from "../components/Dashboard/StatsCards";
import EventTimeline from "../components/Dashboard/EventTimeline";
import SeverityChart from "../components/Dashboard/SeverityChart";
import TopSourcesTable from "../components/Dashboard/TopSourcesTable";
import MitreHeatmap from "../components/Dashboard/MitreHeatmap";
import RecentAlerts from "../components/Dashboard/RecentAlerts";
import { useSummary, useTimeline, useTopSources, useMitreCoverage } from "../hooks/useStats";
import { useAlerts } from "../hooks/useAlerts";

export default function DashboardPage() {
  const { data: summary, isLoading: loadingSummary, error: summaryError } = useSummary();
  const { data: timelineData } = useTimeline(24, 60);
  const { data: sourcesData } = useTopSources(24);
  const { data: mitreData } = useMitreCoverage();
  const { data: alertsData } = useAlerts({ status: ["open"], page: 1, page_size: 10 });

  if (summaryError) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <div className="text-red-400 text-sm font-medium">Cannot connect to SIEM backend</div>
        <div className="text-slate-500 text-xs">Make sure the backend is running on port 8000</div>
        <code className="text-xs text-slate-400 bg-slate-800 px-3 py-1 rounded">
          python -m backend.main
        </code>
      </div>
    );
  }

  if (loadingSummary || !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400 text-sm animate-pulse">Loading security data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <StatsCards summary={summary} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <EventTimeline data={timelineData?.timeline ?? []} />
        </div>
        <SeverityChart breakdown={summary.severity_breakdown} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TopSourcesTable sources={sourcesData?.sources ?? []} />
        <MitreHeatmap coverage={mitreData?.coverage ?? []} />
      </div>

      <RecentAlerts alerts={alertsData?.alerts ?? []} />
    </div>
  );
}
