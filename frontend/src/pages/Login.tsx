import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { login } from "../api";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");
  const nav = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await login(username, password);
      nav("/");
    } catch {
      setError("Invalid username or password.");
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[radial-gradient(circle_at_top,_#1a1440,_#0a0e17)]">
      <form onSubmit={handleSubmit} className="glass rounded-2xl p-8 w-96 shadow-2xl">
        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="text-indigo-400" size={28} />
          <h1 className="text-xl font-bold text-white">ScanChain</h1>
        </div>
        <p className="text-slate-400 text-sm mb-6">Supply Chain Security Platform</p>
        <label className="text-xs text-slate-400">Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)}
          className="w-full mb-4 mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
        <label className="text-xs text-slate-400">Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          className="w-full mb-4 mt-1 bg-slate-900/60 border border-slate-700 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500" />
        {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
        <button className="w-full bg-indigo-600 hover:bg-indigo-500 transition rounded-lg py-2 text-sm font-medium">
          Sign In
        </button>
        <p className="text-slate-500 text-xs mt-4">Default: admin / admin123</p>
      </form>
    </div>
  );
}
