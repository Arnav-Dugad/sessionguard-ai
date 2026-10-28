import { motion } from "framer-motion";
import type { ReactNode } from "react";
import { cn, BAND_META, SEVERITY_META } from "@/lib/utils";

export function Panel({ className, children, title, action, ...rest }: {
  className?: string; children: ReactNode; title?: ReactNode; action?: ReactNode;
} & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("panel p-4", className)} {...rest}>
      {(title || action) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          {typeof title === "string" ? <h3 className="card-title">{title}</h3> : title}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export function BandBadge({ band, className }: { band: string; className?: string }) {
  const m = BAND_META[band] ?? BAND_META["n/a"];
  return (
    <span className={cn("chip", m.bg, m.text, "ring-1", m.ring, className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: m.color }} />
      {m.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  const m = SEVERITY_META[severity] ?? SEVERITY_META.info;
  return <span className={cn("inline-block h-2 w-2 rounded-full", m.dot)} title={m.label} />;
}

export function Chip({ children, className, tone }: { children: ReactNode; className?: string; tone?: "accent" | "cyan" | "muted" | "danger" | "success" | "warning" }) {
  const tones: Record<string, string> = {
    accent: "bg-blue-500/12 text-blue-300 ring-blue-500/25",
    cyan: "bg-cyan-500/12 text-cyan-300 ring-cyan-500/25",
    muted: "bg-slate-500/10 text-slate-300 ring-slate-500/20",
    danger: "bg-red-500/12 text-red-300 ring-red-500/25",
    success: "bg-emerald-500/12 text-emerald-300 ring-emerald-500/25",
    warning: "bg-amber-500/12 text-amber-300 ring-amber-500/25",
  };
  return <span className={cn("chip ring-1", tones[tone ?? "muted"], className)}>{children}</span>;
}

export function StatTile({ label, value, sub, icon, tone = "accent", delay = 0 }: {
  label: string; value: ReactNode; sub?: ReactNode; icon?: ReactNode;
  tone?: "accent" | "cyan" | "success" | "warning" | "critical"; delay?: number;
}) {
  const tones: Record<string, string> = {
    accent: "text-blue-300", cyan: "text-cyan-300", success: "text-emerald-300",
    warning: "text-amber-300", critical: "text-red-300",
  };
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay, ease: [0.16, 1, 0.3, 1] }}
      className="panel p-4"
    >
      <div className="flex items-start justify-between">
        <span className="card-title">{label}</span>
        {icon && <span className={cn("opacity-80", tones[tone])}>{icon}</span>}
      </div>
      <div className="mt-2 text-3xl font-semibold tnum">{value}</div>
      {sub && <div className="mt-1 text-xs text-[color:var(--color-muted)]">{sub}</div>}
    </motion.div>
  );
}

export function Empty({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-[color:var(--color-border-strong)] py-12 text-center">
      {icon && <div className="text-[color:var(--color-faint)]">{icon}</div>}
      <p className="text-sm font-medium text-[color:var(--color-muted)]">{title}</p>
      {hint && <p className="max-w-sm text-xs text-[color:var(--color-faint)]">{hint}</p>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton h-4 w-full", className)} />;
}

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("animate-spin", className)} viewBox="0 0 24 24" fill="none" width="16" height="16">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)}
      className={cn("relative inline-flex h-5 w-9 items-center rounded-full transition-colors", checked ? "bg-blue-500" : "bg-slate-600")}
    >
      <span className={cn("inline-block h-4 w-4 transform rounded-full bg-white transition-transform", checked ? "translate-x-4" : "translate-x-0.5")} />
      {label && <span className="sr-only">{label}</span>}
    </button>
  );
}
