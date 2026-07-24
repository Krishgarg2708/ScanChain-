import { useEffect, useState } from "react";
import { Clock, Trash2, Plus } from "lucide-react";
import { listSchedules, createSchedule, deleteSchedule } from "../api";

export default function Schedules() {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [projectName, setProjectName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [interval, setInterval_] = useState(1440);
  const [error, setError] = useState("");

  function refresh() {
    listSchedules().then(setSchedules).catch((e) => setError(e.message));
  }

  useEffect(() => { refresh(); }, []);

  async function handleCreate() {
    setError("");
    if (!projectName || !repoUrl) {
      setError("Provide a project name and repository URL.");
      return;
    }
    try {
      await createSchedule(projectName, repoUrl, interval);
      setProjectName(""); setRepoUrl("");
      refresh();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function handleDelete(id: number) {
    await deleteSchedule(id);
    refresh();
  }

  return (
    <div className="p-8 max-w-3xl">
      <h1 className="text-2xl font-bold mb-1">Scheduled Scans</h1>
      <p className="text-slate-400 text-sm mb-6">
        Recurring git repository scans, run automatically in the background at a fixed interval.
      </p>

      <div className="glass rounded-xl p-5 mb-6">
        <div className="grid grid-cols-2 gap-4 mb-3">
          <div>
            <label className="text-xs text-slate-400">Project Name</label>
            <input value={projectName} onChange={(e) => setProjectName(e.target.value)}
              className="w-full mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
          </div>
          <div>
            <label className="text-xs text-slate-400">Interval (minutes)</label>
            <input type="number" value={interval} onChange={(e) => setInterval_(Number(e.target.value))}
              className="w-full mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
          </div>
        </div>
        <label className="text-xs text-slate-400">Repository URL</label>
        <input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo.git"
          className="w-full mt-1 mb-3 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
        {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
        <button onClick={handleCreate}
          className="bg-indigo-600 hover:bg-indigo-500 transition rounded-lg px-4 py-2 text-sm font-medium flex items-center gap-1.5">
          <Plus size={14} /> Add Schedule
        </button>
      </div>

      <div className="space-y-2">
        {schedules.length === 0 && <p className="text-slate-500 text-sm">No scheduled scans yet.</p>}
        {schedules.map((s) => (
          <div key={s.id} className="glass rounded-lg px-4 py-3 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">{s.project_name}</div>
              <div className="text-xs text-slate-400">{s.repo_url}</div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-xs text-slate-400 flex items-center gap-1">
                <Clock size={12} /> every {s.interval_minutes}m
              </span>
              <span className="text-xs text-slate-500">
                {s.last_run_at ? `Last run ${new Date(s.last_run_at).toLocaleString()}` : "Not yet run"}
              </span>
              <button onClick={() => handleDelete(s.id)} className="text-slate-500 hover:text-red-400">
                <Trash2 size={14} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
