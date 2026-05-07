import { BookOpen, Activity, Shield, Zap, Search, Bell, FileText, Terminal, AlertTriangle, Database } from "lucide-react";

interface Section {
  id: string;
  icon: React.ElementType;
  title: string;
  content: React.ReactNode;
}

const sections: Section[] = [
  {
    id: "overview",
    icon: Activity,
    title: "How It Works",
    content: (
      <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
        <p>
          This platform is a Security Information and Event Management (SIEM) system — it collects log data from
          your Windows machine in real time, normalizes it into a common format, runs it through detection rules,
          and surfaces alerts when suspicious patterns are found.
        </p>
        <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-400 leading-loose">
          <div className="text-slate-500 mb-2">{"// Data flow"}</div>
          <div><span className="text-blue-400">Windows Event Log</span> → Watcher (poll every 10s) → <span className="text-green-400">FastAPI Backend</span></div>
          <div className="ml-4 text-slate-500">↓</div>
          <div className="ml-4"><span className="text-yellow-400">Parser</span> (normalise fields) → <span className="text-yellow-400">Risk Scorer</span> → <span className="text-yellow-400">SQLite DB</span></div>
          <div className="ml-4 text-slate-500">↓</div>
          <div className="ml-4"><span className="text-purple-400">Correlation Engine</span> (YAML rules) → <span className="text-red-400">Alerts</span></div>
          <div className="ml-4 text-slate-500">↓</div>
          <div className="ml-4"><span className="text-blue-400">React Dashboard</span> (auto-refreshes every 30s)</div>
        </div>
      </div>
    ),
  },
  {
    id: "events",
    icon: Database,
    title: "Windows Events Being Monitored",
    content: (
      <div className="space-y-2">
        <p className="text-sm text-slate-400 mb-3">
          The watcher polls the Security and System logs every 10 seconds and only forwards these specific Event IDs:
        </p>
        <div className="overflow-hidden rounded-lg border border-slate-700">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-800 text-slate-400">
                <th className="text-left px-3 py-2">Event ID</th>
                <th className="text-left px-3 py-2">What It Means</th>
                <th className="text-left px-3 py-2">MITRE Technique</th>
                <th className="text-left px-3 py-2">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {[
                ["4625", "Failed logon attempt", "T1110 Brute Force", "medium"],
                ["4624", "Successful logon (non-system)", "—", "info"],
                ["4672", "Admin privileges assigned at logon", "T1078 Valid Accounts", "medium"],
                ["4740", "Account locked out", "T1110 Brute Force", "high"],
                ["4720", "New user account created", "T1136 Create Account", "medium"],
                ["4697", "Service installed", "T1543 Create Service", "high"],
                ["4698", "Scheduled task created", "T1053 Scheduled Task", "medium"],
                ["4719", "Audit policy changed", "T1562 Defense Evasion", "high"],
                ["4688", "Process created", "—", "low"],
                ["1102", "Security log cleared", "T1070 Indicator Removal", "critical"],
                ["7045", "New service (System log)", "T1543 Create Service", "high"],
                ["7036", "Service state changed", "—", "info"],
              ].map(([id, desc, mitre, sev]) => (
                <tr key={id} className="text-slate-300 hover:bg-slate-700/30">
                  <td className="px-3 py-2 font-mono text-blue-400">{id}</td>
                  <td className="px-3 py-2">{desc}</td>
                  <td className="px-3 py-2 font-mono text-purple-400 text-xs">{mitre}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                      sev === "critical" ? "bg-red-900/50 text-red-400" :
                      sev === "high" ? "bg-orange-900/50 text-orange-400" :
                      sev === "medium" ? "bg-yellow-900/50 text-yellow-400" :
                      sev === "low" ? "bg-blue-900/50 text-blue-400" :
                      "bg-slate-700 text-slate-400"
                    }`}>{sev}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          System account logons (SYSTEM, NETWORK SERVICE, DWM-*, anonymous) are filtered out as noise before ingestion.
        </p>
      </div>
    ),
  },
  {
    id: "risk",
    icon: AlertTriangle,
    title: "Risk Scoring (0–100)",
    content: (
      <div className="space-y-3 text-sm text-slate-300">
        <p>Every event gets a risk score calculated from four factors added together:</p>
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: "Base severity", items: ["critical → 85", "high → 65", "medium → 40", "low → 20", "info → 5"] },
            { label: "Event type bonus", items: ["data_exfiltration +30", "log_cleared +30", "lateral_movement +25", "privilege_escalation +20", "failed_login +10"] },
            { label: "MITRE technique bonus", items: ["T1021 Remote Services +20", "T1070 Indicator Removal +20", "T1078 Valid Accounts +15", "T1110 Brute Force +5"] },
            { label: "Threat intelligence", items: ["Known malicious IP +15", "Internal/clean IP +0"] },
          ].map(({ label, items }) => (
            <div key={label} className="bg-slate-900 rounded-lg p-3">
              <div className="text-xs font-semibold text-slate-400 mb-2">{label}</div>
              {items.map((i) => (
                <div key={i} className="text-xs text-slate-500 font-mono">{i}</div>
              ))}
            </div>
          ))}
        </div>
        <p className="text-xs text-slate-500">
          Example: a failed login (medium=40 + failed_login=10 + T1110=5) = risk score 55.
        </p>
      </div>
    ),
  },
  {
    id: "rules",
    icon: Shield,
    title: "Detection Rules & Alerts",
    content: (
      <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
        <p>
          Rules are defined in YAML files under <code className="bg-slate-900 px-1 rounded text-blue-400">backend/rules/</code>.
          The correlation engine runs every time new events are ingested and looks for patterns across a time window.
        </p>
        <div className="overflow-hidden rounded-lg border border-slate-700">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-800 text-slate-400">
                <th className="text-left px-3 py-2">Rule</th>
                <th className="text-left px-3 py-2">Triggers When</th>
                <th className="text-left px-3 py-2">Technique</th>
                <th className="text-left px-3 py-2">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50 text-slate-300">
              <tr className="hover:bg-slate-700/30">
                <td className="px-3 py-2 font-medium">Brute Force</td>
                <td className="px-3 py-2">5+ failed logins from same IP in 10 min</td>
                <td className="px-3 py-2 font-mono text-purple-400">T1110</td>
                <td className="px-3 py-2 text-orange-400">High</td>
              </tr>
              <tr className="hover:bg-slate-700/30">
                <td className="px-3 py-2 font-medium">Port Scan</td>
                <td className="px-3 py-2">10+ port scan events from same IP in 5 min</td>
                <td className="px-3 py-2 font-mono text-purple-400">T1046</td>
                <td className="px-3 py-2 text-yellow-400">Medium</td>
              </tr>
              <tr className="hover:bg-slate-700/30">
                <td className="px-3 py-2 font-medium">Privilege Escalation</td>
                <td className="px-3 py-2">5+ privilege events from same user in 15 min</td>
                <td className="px-3 py-2 font-mono text-purple-400">T1078</td>
                <td className="px-3 py-2 text-red-400">Critical</td>
              </tr>
              <tr className="hover:bg-slate-700/30">
                <td className="px-3 py-2 font-medium">Lateral Movement</td>
                <td className="px-3 py-2">3+ logins to 3+ different hosts in 30 min</td>
                <td className="px-3 py-2 font-mono text-purple-400">T1021</td>
                <td className="px-3 py-2 text-red-400">Critical</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-slate-400">
          To add your own rule, create a new <code className="bg-slate-900 px-1 rounded text-blue-400">.yaml</code> file
          in <code className="bg-slate-900 px-1 rounded text-blue-400">backend/rules/</code> and restart the backend.
        </p>
      </div>
    ),
  },
  {
    id: "testing",
    icon: Terminal,
    title: "Triggering Real Events (Testing)",
    content: (
      <div className="space-y-4 text-sm text-slate-300">
        <p>Run these in any PowerShell window to generate real security events on your machine:</p>
        {[
          {
            label: "Brute force (triggers alert after 5 failures)",
            code: `1..10 | ForEach-Object {\n  net use \\\\localhost\\ipc$ /user:hacker wrongpassword 2>$null\n  Start-Sleep 1\n}`,
          },
          {
            label: "Service install (high severity — T1543)",
            code: `New-Service -Name "TestSvc" -BinaryPathName "C:\\Windows\\System32\\notepad.exe"\nRemove-Service -Name "TestSvc" -ErrorAction SilentlyContinue`,
          },
          {
            label: "Stop/start a service (System log event 7036)",
            code: `Restart-Service -Name Spooler`,
          },
          {
            label: "Create a scheduled task (T1053)",
            code: `Register-ScheduledTask -TaskName "TestTask" -Action (New-ScheduledTaskAction -Execute "notepad.exe") -RunLevel Highest\nUnregister-ScheduledTask -TaskName "TestTask" -Confirm:$false`,
          },
        ].map(({ label, code }) => (
          <div key={label}>
            <div className="text-xs text-slate-500 mb-1">{label}</div>
            <pre className="bg-slate-900 rounded-lg p-3 text-xs text-green-400 font-mono overflow-x-auto whitespace-pre">
              {code}
            </pre>
          </div>
        ))}
        <p className="text-xs text-slate-500">
          The watcher polls every 10 seconds — events appear in the dashboard within ~10s of being generated.
          Run the backend as Administrator for full Security log access.
        </p>
      </div>
    ),
  },
  {
    id: "pages",
    icon: BookOpen,
    title: "Dashboard Pages Explained",
    content: (
      <div className="space-y-3 text-sm">
        {[
          {
            name: "Dashboard",
            desc: "Overview of all activity. Shows event timeline (last 24h by severity), top attacking IPs, severity distribution, MITRE ATT&CK technique coverage, and the 8 most recent open alerts. Auto-refreshes every 30 seconds.",
          },
          {
            name: "Events",
            desc: "Full searchable log of every event ingested. Filter by time range, severity, source IP, or event type. Click any row to open the detail panel showing raw log, related events, and all parsed fields.",
          },
          {
            name: "Alerts",
            desc: "Correlation rule hits grouped by severity. Each alert links to the specific events that triggered it. Use Open / Acknowledged / Closed / False Positive to track your investigation workflow.",
          },
          {
            name: "Investigation",
            desc: "Forensic pivot tool. Enter an IP address or username to see all activity associated with it — every event, alert, and timeline of behaviour in one view.",
          },
          {
            name: "Rules",
            desc: "Live view of all loaded YAML detection rules, their MITRE mappings, and how many alerts each rule has generated. Edit the YAML files and restart the backend to change thresholds.",
          },
          {
            name: "Wiki (this page)",
            desc: "Reference documentation for the platform — how events flow, what each event ID means, how risk scores are calculated, and how to test it.",
          },
        ].map(({ name, desc }) => (
          <div key={name} className="flex gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <div className="text-sm font-semibold text-slate-200 w-28 flex-shrink-0">{name}</div>
            <div className="text-sm text-slate-400 leading-relaxed">{desc}</div>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: "stack",
    icon: Zap,
    title: "Tech Stack",
    content: (
      <div className="grid grid-cols-2 gap-3 text-sm">
        {[
          { layer: "Backend", tech: "FastAPI (Python)", detail: "REST API, CORS, lifespan startup" },
          { layer: "Database", tech: "SQLite + SQLAlchemy", detail: "WAL mode, zero setup required" },
          { layer: "Frontend", tech: "React 19 + Vite", detail: "TypeScript, Tailwind CSS" },
          { layer: "Charts", tech: "Recharts", detail: "Area, donut, and bar charts" },
          { layer: "Data fetching", tech: "TanStack Query", detail: "30s auto-refresh, optimistic updates" },
          { layer: "Log watcher", tech: "Python + wevtutil", detail: "Polls Windows Event Log via subprocess" },
          { layer: "Rules engine", tech: "YAML + Python", detail: "Sliding window correlation" },
          { layer: "Routing", tech: "React Router v7", detail: "Client-side SPA navigation" },
        ].map(({ layer, tech, detail }) => (
          <div key={layer} className="bg-slate-900 rounded-lg p-3 border border-slate-700/50">
            <div className="text-xs text-slate-500 mb-0.5">{layer}</div>
            <div className="text-sm font-medium text-slate-200">{tech}</div>
            <div className="text-xs text-slate-500 mt-0.5">{detail}</div>
          </div>
        ))}
      </div>
    ),
  },
];

export default function WikiPage() {
  return (
    <div className="flex h-full">
      <div className="w-48 flex-shrink-0 border-r border-slate-700 p-3 overflow-y-auto">
        <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 px-2">Contents</div>
        <nav className="space-y-0.5">
          {sections.map(({ id, icon: Icon, title }) => (
            <a
              key={id}
              href={`#${id}`}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
            >
              <Icon className="w-3 h-3 flex-shrink-0" />
              {title}
            </a>
          ))}
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-blue-400" />
            Platform Wiki
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Reference guide for the Enterprise Security Monitoring Platform
          </p>
        </div>

        {sections.map(({ id, icon: Icon, title, content }) => (
          <section key={id} id={id} className="scroll-mt-4">
            <div className="flex items-center gap-2 mb-4">
              <Icon className="w-4 h-4 text-blue-400" />
              <h2 className="text-base font-semibold text-slate-100">{title}</h2>
            </div>
            <div className="card">
              {content}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
