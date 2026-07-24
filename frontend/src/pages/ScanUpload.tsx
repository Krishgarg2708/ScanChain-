import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { UploadCloud, Loader2, GitBranch } from "lucide-react";
import { uploadScan, scanRepository } from "../api";

export default function ScanUpload() {
  const [mode, setMode] = useState<"upload" | "repo">("upload");
  const [projectName, setProjectName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const nav = useNavigate();

  async function handleScan() {
    setError("");
    if (mode === "upload") {
      if (!file || !projectName) {
        setError("Provide a project name and a file (.zip archive, manifest, or binary).");
        return;
      }
      setLoading(true);
      try {
        const result = await uploadScan(projectName, file);
        nav(`/scans/${result.scan_id}`);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    } else {
      if (!repoUrl || !projectName) {
        setError("Provide a project name and a public git repository URL.");
        return;
      }
      setLoading(true);
      try {
        const result = await scanRepository(projectName, repoUrl);
        nav(`/scans/${result.scan_id}`);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }
  }

  return (
    <div className="p-8 max-w-2xl">
      <h1 className="text-2xl font-bold mb-1">New Scan</h1>
      <p className="text-slate-400 text-sm mb-6">
        Scanning runs entirely against local analyzers (dependency, secrets, binary, license,
        static analysis, container, malware/YARA) plus the free OSV.dev vulnerability database
        — no API key required.
      </p>

      <div className="flex gap-2 mb-4">
        <button onClick={() => setMode("upload")}
          className={`text-sm px-4 py-2 rounded-lg border ${mode === "upload" ? "bg-indigo-600 border-indigo-500" : "border-slate-700 text-slate-400"}`}>
          Upload Project
        </button>
        <button onClick={() => setMode("repo")}
          className={`text-sm px-4 py-2 rounded-lg border flex items-center gap-1.5 ${mode === "repo" ? "bg-indigo-600 border-indigo-500" : "border-slate-700 text-slate-400"}`}>
          <GitBranch size={14} /> Scan Git Repository
        </button>
      </div>

      <div className="glass rounded-xl p-6">
        <label className="text-xs text-slate-400">Project Name</label>
        <input value={projectName} onChange={(e) => setProjectName(e.target.value)}
          placeholder="my-service"
          className="w-full mb-5 mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />

        {mode === "upload" ? (
          <label className="flex flex-col items-center justify-center border-2 border-dashed border-slate-700 rounded-xl py-10 cursor-pointer hover:border-indigo-500 transition">
            <UploadCloud className="text-indigo-400 mb-2" size={28} />
            <span className="text-sm text-slate-300">{file ? file.name : "Drop a file or click to browse"}</span>
            <span className="text-xs text-slate-500 mt-1">.zip project, manifest, Dockerfile, or binary</span>
            <input type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          </label>
        ) : (
          <div>
            <label className="text-xs text-slate-400">Public Git Repository URL</label>
            <input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo.git"
              className="w-full mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
            <p className="text-xs text-slate-500 mt-2">
              Clones a shallow copy and walks recent commit history for leaked secrets — including
              credentials introduced and later "removed" in a follow-up commit.
            </p>
          </div>
        )}

        {error && <p className="text-red-400 text-xs mt-4">{error}</p>}

        <button onClick={handleScan} disabled={loading}
          className="w-full mt-6 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 transition rounded-lg py-2.5 text-sm font-medium flex items-center justify-center gap-2">
          {loading && <Loader2 className="animate-spin" size={16} />}
          {loading ? "Scanning…" : "Run Security Scan"}
        </button>
      </div>
    </div>
  );
}
