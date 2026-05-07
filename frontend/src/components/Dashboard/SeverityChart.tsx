import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import type { StatsSummary } from "../../types";

interface Props {
  breakdown: StatsSummary["severity_breakdown"];
}

const COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
};

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: unknown[] }) => {
  if (!active || !payload?.length) return null;
  const item = (payload as { name: string; value: number }[])[0];
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg p-2 text-xs shadow-xl">
      <span className="text-slate-200 capitalize font-medium">{item.name}: </span>
      <span className="text-slate-100">{item.value.toLocaleString()}</span>
    </div>
  );
};

export default function SeverityChart({ breakdown }: Props) {
  const data = Object.entries(breakdown)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => {
      const order = ["critical", "high", "medium", "low", "info"];
      return order.indexOf(a.name) - order.indexOf(b.name);
    });

  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 mb-4">
        Severity Distribution <span className="text-slate-500 font-normal">(24h)</span>
      </h3>
      <div className="flex items-center gap-4">
        <ResponsiveContainer width={140} height={140}>
          <PieChart>
            <Pie data={data} dataKey="value" cx="50%" cy="50%" innerRadius={40} outerRadius={65} strokeWidth={0}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name] ?? "#64748b"} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="flex-1 space-y-1.5">
          {data.map((entry) => (
            <div key={entry.name} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[entry.name] }} />
                <span className="text-slate-400 capitalize">{entry.name}</span>
              </div>
              <div className="text-right">
                <span className="text-slate-200 font-medium">{entry.value.toLocaleString()}</span>
                <span className="text-slate-500 ml-1">({total > 0 ? Math.round((entry.value / total) * 100) : 0}%)</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
