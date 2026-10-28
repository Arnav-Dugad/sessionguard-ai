import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ReactNode } from "react";

export const CHART = {
  grid: "rgba(255,255,255,0.06)",
  axis: "#64748b",
  accent: "#3b82f6",
  cyan: "#06b6d4",
  success: "#10b981",
  warning: "#f59e0b",
  critical: "#ef4444",
  categorical: ["#3b82f6", "#06b6d4", "#8b5cf6", "#f59e0b", "#10b981", "#ef4444", "#ec4899", "#14b8a6"],
};

function TT({ active, payload, label, fmt }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-[color:var(--color-border-strong)] bg-[color:var(--color-overlay)]/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      {label !== undefined && <div className="mb-1 font-mono text-[11px] text-[color:var(--color-muted)]">{fmt ? fmt(label) : label}</div>}
      {payload.map((p: any, i: number) => (
        <div key={i} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: p.color || p.fill }} />
          <span className="text-[color:var(--color-muted)]">{p.name}</span>
          <span className="ml-auto font-mono font-semibold text-[color:var(--color-ink)]">{typeof p.value === "number" ? p.value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : p.value}</span>
        </div>
      ))}
    </div>
  );
}

const axisProps = { stroke: CHART.axis, fontSize: 11, tickLine: false, axisLine: false };

export function RiskAreaChart({ data, fmtX }: { data: any[]; fmtX?: (v: any) => string }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="riskArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={CHART.accent} stopOpacity={0.5} />
            <stop offset="100%" stopColor={CHART.accent} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey="t" {...axisProps} tickFormatter={fmtX} minTickGap={40} />
        <YAxis domain={[0, 100]} {...axisProps} width={38} />
        <Tooltip content={<TT fmt={fmtX} />} />
        <Area type="monotone" dataKey="risk_avg" name="Avg risk" stroke={CHART.accent} strokeWidth={2} fill="url(#riskArea)" connectNulls />
        <Line type="monotone" dataKey="risk_max" name="Max risk" stroke={CHART.critical} strokeWidth={1.5} dot={false} connectNulls />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function StackedActivityChart({ data, fmtX }: { data: any[]; fmtX?: (v: any) => string }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey="t" {...axisProps} tickFormatter={fmtX} minTickGap={40} />
        <YAxis {...axisProps} width={28} allowDecimals={false} />
        <Tooltip content={<TT fmt={fmtX} />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
        <Bar dataKey="normal" name="Normal" stackId="a" fill={CHART.success} radius={[0, 0, 0, 0]} />
        <Bar dataKey="suspicious" name="Suspicious" stackId="a" fill={CHART.warning} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function SimpleBar({ data, x, y, color = CHART.accent, height = 200, horizontal = false }: {
  data: any[]; x: string; y: string; color?: string; height?: number; horizontal?: boolean;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout={horizontal ? "vertical" : "horizontal"} margin={{ top: 6, right: 12, left: horizontal ? 10 : -20, bottom: 0 }}>
        <CartesianGrid stroke={CHART.grid} vertical={!horizontal} horizontal={horizontal} />
        {horizontal ? <>
          <XAxis type="number" {...axisProps} allowDecimals={false} />
          <YAxis type="category" dataKey={x} {...axisProps} width={120} />
        </> : <>
          <XAxis dataKey={x} {...axisProps} interval={0} angle={0} />
          <YAxis {...axisProps} width={32} allowDecimals={false} />
        </>}
        <Tooltip content={<TT />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
        <Bar dataKey={y} fill={color} radius={horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]}>
          {data.map((_, i) => <Cell key={i} fill={color} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryBar({ data, x, y, height = 200 }: { data: any[]; x: string; y: string; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 12, left: -20, bottom: 0 }}>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey={x} {...axisProps} interval={0} tick={{ fontSize: 10 }} />
        <YAxis {...axisProps} width={32} allowDecimals={false} />
        <Tooltip content={<TT />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
        <Bar dataKey={y} radius={[4, 4, 0, 0]}>
          {data.map((_, i) => <Cell key={i} fill={CHART.categorical[i % CHART.categorical.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Donut({ data, height = 200 }: { data: { name: string; value: number }[]; height?: number }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="82%" paddingAngle={2} stroke="none">
          {data.map((_, i) => <Cell key={i} fill={CHART.categorical[i % CHART.categorical.length]} />)}
        </Pie>
        <Tooltip content={<TT />} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function ChartFrame({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="panel p-4">
      <div className="mb-3 flex items-center justify-between"><h3 className="card-title">{title}</h3>{right}</div>
      {children}
    </div>
  );
}
