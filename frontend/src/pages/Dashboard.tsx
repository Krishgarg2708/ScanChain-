import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ShieldAlert, Activity, FileWarning } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { getDashboardStats } from "../api";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#64748b",
};

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getDashboardStats().then(setStats).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="p-8 text-red-400">{error}</div>;
  if (!stats) return <div className="p-8 text-slate-400">Loading dashboard…</div>;

  const pieData = Object.entries(stats.severity_counts)
    .filter(([, v]) => (v as number) > 0)
    .map(([k, v]) => ({ name: k, value: v }));

  const cards = [
    { label: "Total Scans", value: stats.total_scans, icon: Activity, color: "text-indigo-400" },
    { label: "Total Findings", value: stats.total_findings, icon: FileWarning, color: "text-orange-400" },
    { label: "Avg Risk Score", value: stats.average_risk_score, icon: ShieldAlert, color: "text-red-400" },
    { label: "Critical Findings", value: stats.severity_counts.critical, icon: AlertTriangle, color: "text-red-500" },
  ];

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-1">Security Overview</h1>
      <p className="text-slate-400 text-sm mb-6">Real-time supply chain risk posture</p>

      <div className="grid grid-cols-4 gap-4 mb-8">
        {cards.map((c) => (
          <div key={c.label} className="glass rounded-xl p-5">
            <c.icon className={`${c.color} mb-2`} size={20} />
            <div className="text-2xl font-bold">{c.value}</div>
            <div className="text-xs text-slate-400 mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="glass rounded-xl p-5 col-span-1">
          <h2 className="text-sm font-semibold mb-4 text-slate-300">Findings by Severity</h2>
          {pieData.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#141a29", border: "1px solid #2d3348" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-500 text-sm">No findings yet. Run a scan to populate this chart.</p>}
        </div>

        <div className="glass rounded-xl p-5 col-span-2">
          <h2 className="text-sm font-semibold mb-4 text-slate-300">Recent Scans</h2>
          <div className="space-y-2">
            {stats.recent_scans.length === 0 && (
              <p className="text-slate-500 text-sm">No scans yet — upload a project to get started.</p>
            )}
            {stats.recent_scans.map((s: any) => (
              <Link to={`/scans/${s.id}`} key={s.id}
                className="flex items-center justify-between bg-slate-900/40 hover:bg-slate-900/70 transition rounded-lg px-4 py-3 text-sm">
                <span>Scan #{s.id}</span>
                <span className="text-slate-400">{new Date(s.created_at).toLocaleString()}</span>
                <span className={`font-semibold ${s.risk_score > 60 ? "text-red-400" : s.risk_score > 30 ? "text-orange-400" : "text-green-400"}`}>
                  Risk {s.risk_score}
                </span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
