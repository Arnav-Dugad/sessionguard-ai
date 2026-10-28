import { NavLink, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, ShieldAlert, LayoutDashboard, Radar, ListTree, BrainCircuit, SlidersHorizontal,
  GitCompareArrows, Presentation, Settings, UserRound, FlaskConical, LogOut, ShieldCheck, Menu, X,
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

const ADMIN_NAV = [
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/sessions", label: "Active Sessions", icon: ListTree },
  { to: "/threats", label: "Threat Detection", icon: ShieldAlert },
  { to: "/lab", label: "Attack Simulation Lab", icon: FlaskConical },
  { to: "/events", label: "Live Security Events", icon: Activity },
  { to: "/analytics", label: "Risk Analytics", icon: Radar },
  { to: "/models", label: "ML Model Evaluation", icon: BrainCircuit },
  { to: "/policy", label: "Zero-Trust Policy", icon: SlidersHorizontal },
  { to: "/comparison", label: "Experimental Comparison", icon: GitCompareArrows },
  { to: "/presentation", label: "Presentation Mode", icon: Presentation },
  { to: "/settings", label: "System Settings", icon: Settings },
];
const USER_NAV = [{ to: "/portal", label: "User Portal", icon: UserRound }];

export function Brand({ compact }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 shadow-[0_0_24px_-4px_rgba(59,130,246,0.7)]">
        <ShieldCheck size={20} className="text-white" />
      </div>
      {!compact && (
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">SessionGuard<span className="text-blue-400"> AI</span></div>
          <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--color-faint)]">Detect · Analyze · Contain</div>
        </div>
      )}
    </div>
  );
}

function NavItem({ to, label, icon: Icon, onClick }: { to: string; label: string; icon: any; onClick?: () => void }) {
  return (
    <NavLink to={to} onClick={onClick} className={({ isActive }) =>
      cn("group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
        isActive ? "text-white" : "text-[color:var(--color-muted)] hover:text-white hover:bg-white/5")
    }>
      {({ isActive }) => (
        <>
          {isActive && (
            <motion.span layoutId="nav-active" className="absolute inset-0 rounded-lg bg-blue-500/15 ring-1 ring-blue-500/30" transition={{ type: "spring", stiffness: 400, damping: 32 }} />
          )}
          <Icon size={17} className={cn("relative z-10 shrink-0", isActive && "text-blue-300")} />
          <span className="relative z-10 truncate">{label}</span>
        </>
      )}
    </NavLink>
  );
}

export function AppLayout({ children }: { children: ReactNode }) {
  const { user, session, logout } = useAuth();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  const nav = user?.role === "admin" ? [...ADMIN_NAV, ...USER_NAV] : USER_NAV;

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className={cn(
        "fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-[color:var(--color-border)] bg-[color:var(--color-surface)]/80 backdrop-blur-xl transition-transform lg:static lg:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex items-center justify-between p-4"><Brand /><button className="lg:hidden" onClick={() => setOpen(false)}><X size={18} /></button></div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
          {user?.role === "admin" && <div className="px-3 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-wider text-[color:var(--color-faint)]">Security Operations</div>}
          {nav.map((n) => <NavItem key={n.to} {...n} onClick={() => setOpen(false)} />)}
        </nav>
        <div className="border-t border-[color:var(--color-border)] p-3">
          <div className="mb-2 flex items-center gap-2.5 rounded-lg px-2 py-1.5">
            <div className="grid h-8 w-8 place-items-center rounded-full bg-[color:var(--color-elevated)] text-xs font-semibold">
              {(user?.display_name || user?.username || "?").slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 leading-tight">
              <div className="truncate text-xs font-medium">{user?.display_name || user?.username}</div>
              <div className="text-[10px] text-[color:var(--color-faint)]">{user?.role === "admin" ? "SOC Administrator" : "Standard user"}</div>
            </div>
          </div>
          <button className="btn btn-ghost w-full justify-start text-sm" onClick={logout}><LogOut size={15} /> Sign out</button>
        </div>
      </aside>

      {open && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setOpen(false)} />}

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-[color:var(--color-border)] bg-[color:var(--color-bg)]/70 px-4 py-3 backdrop-blur-xl lg:px-6">
          <button className="lg:hidden" onClick={() => setOpen(true)}><Menu size={20} /></button>
          <div className="min-w-0 flex-1" />
          {session && session.protection_mode && (
            <span className="hidden items-center gap-1.5 text-xs text-[color:var(--color-muted)] sm:flex">
              <span className="live-dot" /> session <span className="font-mono text-[color:var(--color-ink)]">{session.id}</span>
            </span>
          )}
        </header>
        <main className="min-w-0 flex-1 p-4 lg:p-6">
          <AnimatePresence mode="wait">
            <motion.div key={loc.pathname} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}>
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions, icon: Icon }: { title: string; subtitle?: ReactNode; actions?: ReactNode; icon?: any }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="flex items-start gap-3">
        {Icon && <div className="mt-0.5 grid h-10 w-10 place-items-center rounded-xl bg-[color:var(--color-elevated)] ring-1 ring-[color:var(--color-border-strong)]"><Icon size={20} className="text-blue-300" /></div>}
        <div>
          <h1 className="text-xl font-semibold tracking-tight lg:text-2xl">{title}</h1>
          {subtitle && <p className="mt-0.5 max-w-2xl text-sm text-[color:var(--color-muted)]">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
