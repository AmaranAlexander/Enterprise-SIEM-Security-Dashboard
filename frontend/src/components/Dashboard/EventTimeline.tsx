import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { fmtChartTime } from "../../utils/time";
import type { TimelineBucket } from "../../types";

interface Props {
  data: TimelineBucket[];
}

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
};

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: unknown[]; label?: string }) => {
  if (!active || !payload?.length) return null;
  const items = payload as { name: string; value: number; color: string }[];
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-300 mb-2 font-medium">{label}</p>
      {items.map((item) => (
        <div key={item.name} className="flex items-center gap-2 mb-1">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
          <span className="text-slate-400 capitalize">{item.name}:</span>
          <span className="text-slate-100 font-medium">{item.value}</span>
        </div>
      ))}
    </div>
  );
};

export default function EventTimeline({ data }: Props) {
  const formatted = data.map((d) => ({
    ...d,
    time: fmtChartTime(d.time),
  }));

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 mb-4">Event Timeline (24h)</h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={formatted} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
          <defs>
            {(Object.entries(COLORS) as [string, string][]).map(([key, color]) => (
              <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0.0} />
              </linearGradient>
            ))}
          </defs>
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#64748b" }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fontSize: 10, fill: "#64748b" }} tickLine={false} axisLine={false} />
          <Tooltip content={<CustomTooltip />} />
          {(Object.entries(COLORS) as [string, string][]).map(([key, color]) => (
            <Area
              key={key}
              type="monotone"
              dataKey={key}
              stroke={color}
              strokeWidth={1.5}
              fill={`url(#grad-${key})`}
              stackId="1"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
