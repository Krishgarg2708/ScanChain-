import { useEffect, useState, useRef } from "react";
import { useParams } from "react-router-dom";
import { Download, Terminal, Crosshair } from "lucide-react";
import { getScan, downloadReport, getMitreMapping, scanLogSocketUrl } from "../api";

const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState<any>(null);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");
  const [mitre, setMitre] = useState<any>(null);
  const [logs, setLogs] = useState<{ level: string; message: string }[]>([]);
  const [showLogs, setShowLogs] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    getScan(Number(id)).then(setScan).catch((e) => setError(e.message));
    getMitreMapping(Number(id)).then(setMitre).catch(() => {});
  }, [id]);

  useEffect(() => {
    if (!showLogs || !id) return;
    const ws = new WebSocket(scanLogSocketUrl(Number(id)));
    wsRef.current = ws;
    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data);
      if (data.message === "__DONE__") return;
      setLogs((prev) => [...prev, data]);
    };
    return () => ws.close();
  }, [showLogs, id]);

  if (error) return <div className="p-8 text-red-400">{error}</div>;
  if (!scan) return <div className="p-8 text-slate-400">Loading scan…</div>;

  const findings = filter === "all" ? scan.findings : scan.findings.filter((f: any) => f.severity === filter);

  function downloadSbom() {
    const blob = new Blob([JSON.stringify(scan.summary.sbom, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbom-scan-${scan.id}.json`;
    a.click();
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scan #{scan.id}</h1>
          <p className="text-slate-400 text-sm">{new Date(scan.created_at).toLocaleString()}</p>
        </div>
        <div className="flex items-center gap-4">
          <button onClick={() => setShowLogs((s) => !s)}
            className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg flex items-center gap-1.5">
            <Terminal size={14} /> {showLogs ? "Hide Logs" : "View Scan Logs"}
          </button>
          <div className="flex items-center gap-1 bg-slate-900/60 rounded-lg p-1">
            {["html", "markdown", "csv", "pdf"].map((fmt) => (
              <button key={fmt} onClick={() => downloadReport(scan.id, fmt, `scan-${scan.id}`)}
                className="text-xs px-2.5 py-1.5 rounded-md text-slate-300 hover:bg-slate-800 flex items-center gap-1">
                <Download size={12} /> {fmt.toUpperCase()}
              </button>
            ))}
          </div>
          <button onClick={downloadSbom} className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg">
            SBOM
          </button>
          <div className={`text-3xl font-bold ${scan.risk_score > 60 ? "text-red-400" : scan.risk_score > 30 ? "text-orange-400" : "text-green-400"}`}>
            {scan.risk_score}
            <span className="text-xs text-slate-400 font-normal block text-right">Risk Score</span>
          </div>
        </div>
      </div>

      {showLogs && (
        <div className="glass rounded-xl p-4 mb-4 bg-black/40 font-mono text-xs max-h-64 overflow-y-auto">
          {logs.length === 0 && <div className="text-slate-500">Connecting…</div>}
          {logs.map((l, i) => (
            <div key={i} className="text-green-400">
              <span className="text-slate-600">$</span> {l.message}
            </div>
          ))}
        </div>
      )}

      {mitre && mitre.techniques.length > 0 && (
        <div className="glass rounded-xl p-5 mb-4">
          <h2 className="text-sm font-semibold mb-3 text-slate-300 flex items-center gap-2">
            <Crosshair size={14} /> MITRE ATT&amp;CK Coverage
          </h2>
          <div className="flex flex-wrap gap-2 mb-3">
            {mitre.tactics_covered.map((t: string) => (
              <span key={t} className="text-xs bg-purple-500/15 text-purple-300 border border-purple-500/30 px-2.5 py-1 rounded-full">
                {t}
              </span>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            {mitre.techniques.map((t: any) => (
              <div key={t.technique_id} className="text-xs bg-slate-900/40 rounded-lg px-3 py-2 flex justify-between">
                <span>{t.technique_id} — {t.technique_name}</span>
                <span className="text-slate-500">×{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-2 mb-4">
        {["all", "critical", "high", "medium", "low", "info"].map((s) => (
          <button key={s} onClick={() => setFilter(s)}
            className={`text-xs px-3 py-1.5 rounded-full border ${filter === s ? "bg-indigo-600 border-indigo-500" : "border-slate-700 text-slate-400"}`}>
            {s} {s !== "all" ? `(${scan.summary.risk.severity_counts[s] || 0})` : `(${scan.findings.length})`}
          </button>
        ))}
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-slate-400 text-xs uppercase">
            <tr>
              <th className="text-left px-4 py-3">Severity</th>
              <th className="text-left px-4 py-3">Finding</th>
              <th className="text-left px-4 py-3">Location</th>
              <th className="text-left px-4 py-3">CVSS</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f: any) => (
              <tr key={f.id} className="border-t border-slate-800 hover:bg-slate-900/30">
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-1 rounded-full border ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
                </td>
                <td className="px-4 py-3">
                  <div className="font-medium">{f.title}</div>
                  <div className="text-slate-400 text-xs mt-0.5">{f.description}</div>
                  {f.remediation && <div className="text-indigo-400 text-xs mt-1">Fix: {f.remediation}</div>}
                </td>
                <td className="px-4 py-3 text-slate-400 font-mono text-xs">{f.location}</td>
                <td className="px-4 py-3 text-slate-300">{f.cvss ?? "—"}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={4} className="text-center text-slate-500 py-8">No findings in this category.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
