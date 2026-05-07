import { useQuery } from "@tanstack/react-query";
import { rulesApi } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";
import { Shield, AlertTriangle, CheckCircle } from "lucide-react";

const TACTIC_LABELS: Record<string, string> = {
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Movement",
  "collection": "Collection",
  "exfiltration": "Exfiltration",
};

export default function RulesPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["rules"],
    queryFn: rulesApi.list,
  });

  if (isLoading) {
    return <div className="text-center text-slate-400 py-8 animate-pulse">Loading detection rules...</div>;
  }

  const rules = data?.rules ?? [];
  const totalAlerts = rules.reduce((s, r) => s + r.total_alerts, 0);
  const openAlerts = rules.reduce((s, r) => s + r.open_alerts, 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="card text-center">
          <div className="text-2xl font-bold text-slate-100">{rules.length}</div>
          <div className="text-xs text-slate-400 mt-1">Detection Rules</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-slate-100">{totalAlerts}</div>
          <div className="text-xs text-slate-400 mt-1">Total Alerts Generated</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-red-400">{openAlerts}</div>
          <div className="text-xs text-slate-400 mt-1">Open Alerts</div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-4 h-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-slate-300">Detection Rules</h3>
        </div>
        <p className="text-xs text-slate-500 mb-4">
          Rules are defined in YAML files in <code className="bg-slate-700 px-1 rounded text-slate-300">backend/rules/</code>.
          Each rule maps to a MITRE ATT&CK® technique and triggers when correlation conditions are met.
        </p>

        <div className="space-y-3">
          {rules.map((rule) => (
            <div key={rule.id} className="border border-slate-700 rounded-lg p-4">
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <SeverityBadge severity={rule.severity} />
                    {rule.mitre_technique && (
                      <span className="font-mono text-xs text-blue-400 bg-blue-900/30 px-2 py-0.5 rounded border border-blue-800/50">
                        {rule.mitre_technique}
                      </span>
                    )}
                    {rule.mitre_tactic && (
                      <span className="text-xs text-slate-400 bg-slate-700/50 px-2 py-0.5 rounded">
                        {TACTIC_LABELS[rule.mitre_tactic] ?? rule.mitre_tactic}
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">{rule.name}</h4>
                </div>
                <div className="text-right flex-shrink-0">
                  <div className="text-lg font-bold text-slate-200">{Math.round(rule.risk_score)}</div>
                  <div className="text-xs text-slate-500">risk score</div>
                </div>
              </div>

              <p className="text-xs text-slate-400 mb-3 leading-relaxed">{rule.description}</p>

              <div className="space-y-1.5 mb-3">
                <div className="text-xs text-slate-500 uppercase tracking-wide">Conditions</div>
                {rule.condition_summary.map((summary, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs text-slate-300">
                    <span className="text-blue-400 font-mono w-4">{i + 1}.</span>
                    {summary}
                  </div>
                ))}
              </div>

              <div className="flex items-center gap-4 text-xs border-t border-slate-700 pt-3">
                <span className="text-slate-500">Rule ID: <span className="font-mono text-slate-300">{rule.id}</span></span>
                <div className="flex items-center gap-1.5">
                  {rule.open_alerts > 0 ? (
                    <AlertTriangle className="w-3 h-3 text-orange-400" />
                  ) : (
                    <CheckCircle className="w-3 h-3 text-green-500" />
                  )}
                  <span className={rule.open_alerts > 0 ? "text-orange-400" : "text-slate-500"}>
                    {rule.open_alerts} open / {rule.total_alerts} total alerts
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 mb-2">How to Add a Rule</h3>
        <p className="text-xs text-slate-400 mb-3">
          Create a new YAML file in <code className="bg-slate-700 px-1 rounded text-slate-300">backend/rules/</code> and restart the backend.
        </p>
        <pre className="text-xs text-slate-300 bg-slate-900 rounded-lg p-4 overflow-x-auto">{`id: my_custom_rule
name: "Custom Detection Rule"
description: "Describe what this detects and why it matters."
mitre_technique: "T1XXX"
mitre_tactic: "tactic-name"
severity: high
risk_score: 75
conditions:
  - event_type: event_type_name
    min_count: 3
    window_minutes: 10
    group_by: source_ip
alert_template: "Alert: {source_ip} triggered this rule"
`}</pre>
      </div>
    </div>
  );
}
