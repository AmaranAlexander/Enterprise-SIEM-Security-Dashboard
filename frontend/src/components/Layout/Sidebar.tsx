import { NavLink } from "react-router-dom";
import { LayoutDashboard, List, Bell, Search, Shield, Activity, BookOpen } from "lucide-react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/events", icon: List, label: "Events" },
  { to: "/alerts", icon: Bell, label: "Alerts" },
  { to: "/investigation", icon: Search, label: "Investigation" },
  { to: "/rules", icon: Shield, label: "Rules" },
  { to: "/wiki", icon: BookOpen, label: "Wiki" },
];

export default function Sidebar() {
  return (
    <aside className="w-56 bg-slate-900 border-r border-slate-700 flex flex-col flex-shrink-0">
      <div className="p-4 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          <div>
            <div className="text-sm font-semibold text-slate-100">SIEM Platform</div>
            <div className="text-xs text-slate-500">Security Operations</div>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-0.5">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-600/20 text-blue-400 border border-blue-600/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              }`
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-slate-700">
        <div className="text-xs text-slate-600 text-center">Built by Amaran Alexander</div>
      </div>
    </aside>
  );
}
