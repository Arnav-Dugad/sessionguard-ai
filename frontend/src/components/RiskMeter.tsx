import { motion, useMotionValue, useSpring, useTransform } from "framer-motion";
import { useEffect } from "react";
import { bandFor, BAND_META } from "@/lib/utils";
import type { Contribution } from "@/lib/types";

// Animated semicircular risk gauge. The needle and arc spring to the new value; the numeric
// readout counts up. Respects prefers-reduced-motion via Framer's reducedMotion handling.
export function RiskMeter({ value, size = 220 }: { value: number; size?: number }) {
  const band = bandFor(value);
  const meta = BAND_META[band];
  const mv = useMotionValue(0);
  const spring = useSpring(mv, { stiffness: 90, damping: 18 });
  const display = useTransform(spring, (v) => Math.round(v));
  const r = size / 2 - 16;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = Math.PI * r; // semicircle
  const dash = useTransform(spring, (v) => `${(v / 100) * circumference} ${circumference}`);
  const angle = useTransform(spring, (v) => -90 + (v / 100) * 180);

  useEffect(() => {
    mv.set(Math.max(0, Math.min(100, value)));
  }, [value, mv]);

  const thresholds = [25, 50, 75];
  return (
    <div className="relative flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={size / 2 + 28} viewBox={`0 0 ${size} ${size / 2 + 28}`}>
        <defs>
          <linearGradient id="riskgrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="45%" stopColor="#f59e0b" />
            <stop offset="75%" stopColor="#fb923c" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="var(--color-elevated)" strokeWidth="14" strokeLinecap="round" />
        <motion.path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="url(#riskgrad)"
          strokeWidth="14" strokeLinecap="round" style={{ strokeDasharray: dash }}
        />
        {thresholds.map((t) => {
          const a = (-90 + (t / 100) * 180) * (Math.PI / 180);
          const x1 = cx + (r - 9) * Math.cos(a), y1 = cy + (r - 9) * Math.sin(a);
          const x2 = cx + (r + 9) * Math.cos(a), y2 = cy + (r + 9) * Math.sin(a);
          return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--color-bg)" strokeWidth="2" />;
        })}
        <motion.line
          x1={cx} y1={cy} x2={cx} y2={cy - r + 20} stroke={meta.color} strokeWidth="3" strokeLinecap="round"
          style={{ rotate: angle, originX: `${cx}px`, originY: `${cy}px` }}
        />
        <circle cx={cx} cy={cy} r="7" fill={meta.color} />
      </svg>
      <div className="-mt-6 flex flex-col items-center">
        <motion.span className="text-4xl font-semibold tnum" style={{ color: meta.color }}>
          {display}
        </motion.span>
        <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: meta.color }}>{meta.label} risk</span>
      </div>
    </div>
  );
}

export function ContributionBars({ contributions }: { contributions: Record<string, Contribution> }) {
  const items = Object.entries(contributions).sort((a, b) => b[1].points - a[1].points);
  const max = Math.max(1, ...items.map(([, c]) => c.points));
  if (items.length === 0) return <p className="text-xs text-[color:var(--color-faint)]">No contributing factors — risk is at baseline.</p>;
  return (
    <div className="space-y-2.5">
      {items.map(([key, c], i) => (
        <motion.div key={key} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}>
          <div className="mb-1 flex items-center justify-between text-xs">
            <span className="flex items-center gap-1.5 text-[color:var(--color-muted)]">
              {c.label}
              {c.synthetic && <span className="chip bg-fuchsia-500/12 text-fuchsia-300 ring-1 ring-fuchsia-500/25">synthetic</span>}
            </span>
            <span className="font-mono font-semibold text-[color:var(--color-ink)]">+{c.points.toFixed(1)}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-[color:var(--color-elevated)]">
            <motion.div
              className="h-full rounded-full"
              style={{ background: key === "ml" ? "var(--color-cyan)" : key === "carry_over" ? "var(--color-faint)" : "var(--color-accent)" }}
              initial={{ width: 0 }} animate={{ width: `${(c.points / max) * 100}%` }} transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            />
          </div>
          {c.detail && <p className="mt-1 text-[11px] text-[color:var(--color-faint)]">{c.detail}</p>}
        </motion.div>
      ))}
    </div>
  );
}
