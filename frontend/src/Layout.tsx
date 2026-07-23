import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { ShieldCheck, LayoutDashboard, ScanLine, LogOut, Clock } from "lucide-react";
import { logout } from "./api";

export default function Layout() {
  const nav = useNavigate();
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm transition ${
      isActive ? "bg-indigo-600/20 text-indigo-300 border border-indigo-500/30" : "text-slate-400 hover:bg-slate-800/60"
    }`;

  return (
    <div className="flex min-h-screen bg-[#0a0e17]">
      <aside className="w-60 glass flex flex-col p-4 border-r border-slate-800">
        <div className="flex items-center gap-2 px-2 mb-8 mt-2">
          <ShieldCheck className="text-indigo-400" size={24} />
          <span className="font-bold text-white">ScanChain</span>
        </div>
        <nav className="flex flex-col gap-1">
          <NavLink to="/" end className={linkClass}><LayoutDashboard size={16} /> Dashboard</NavLink>
          <NavLink to="/scan/new" className={linkClass}><ScanLine size={16} /> New Scan</NavLink>
          <NavLink to="/schedules" className={linkClass}><Clock size={16} /> Scheduled Scans</NavLink>
        </nav>
        <button
          onClick={() => { logout(); nav("/login"); }}
          className="mt-auto flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm text-slate-400 hover:bg-slate-800/60">
          <LogOut size={16} /> Sign Out
        </button>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
