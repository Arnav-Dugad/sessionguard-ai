import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar, Timer } from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/Layout";
import { Panel, StatTile, Empty } from "@/components/ui";
import { RiskAreaChart, StackedActivityChart, CategoryBar, Donut, SimpleBar, ChartFrame } from "@/components/charts";
import { fmtTime } from "@/lib/utils";

const WINDOWS = [{ m: 60, l: "1h" }, { m: 360, l: "6h" }, { m: 1440, l: "24h" }];

export default function Analytics() {
  const [win, setWin] = useState(60);
  const { data, isLoading } = useQuery({ queryKey: ["analytics", win], queryFn: () => api.get<any>(`/security/metrics?window_minutes=${win}&buckets=36`), refetchInterval: 8000 });
  const fmtX = (t: string) => fmtTime(t);

  const outcomes = (data?.detection_outcomes ?? []).map((d: any) => ({ name: d.decision, value: d.count }));
  const threats = data?.threats_by_category ?? [];
  const dist = data?.risk_distribution ?? [];

  return (
    <div>
      <PageHeader title="Risk Analytics" icon={Radar}
        subtitle="Aggregated, time-bucketed analytics computed from stored risk assessments and events."
        actions={
          <div className="flex overflow-hidden rounded-lg border border-[color:var(--color-border-strong)]">
            {WINDOWS.map((w) => <button key={w.m} onClick={() => setWin(w.m)} className={`px-3 py-1.5 text-xs font-medium ${win === w.m ? "bg-blue-500 text-white" : "bg-[color:var(--color-elevated)] text-[color:var(--color-muted)]"}`}>{w.l}</button>)}
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile label="Assessments" value={data?.totals?.assessments ?? "—"} tone="accent" />
        <StatTile label="Events" value={data?.totals?.events ?? "—"} tone="cyan" />
        <StatTile label="Suspicious share" value={data ? `${(data.totals.suspicious_share * 100).toFixed(1)}%` : "—"} tone="warning" />
        <StatTile label="Window" value={WINDOWS.find((w) => w.m === win)?.l} sub={`${data?.series?.length ?? 0} buckets`} tone="success" />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <ChartFrame title="Session risk over time">{data?.series ? <RiskAreaChart data={data.series} fmtX={fmtX} /> : <div className="skeleton h-[220px]" />}</ChartFrame>
        <ChartFrame title="Normal vs suspicious">{data?.series ? <StackedActivityChart data={data.series} fmtX={fmtX} /> : <div className="skeleton h-[220px]" />}</ChartFrame>
        <ChartFrame title="Active sessions over time">
          {data?.series ? <SessionsArea data={data.series} fmtX={fmtX} /> : <div className="skeleton h-[220px]" />}
        </ChartFrame>
        <ChartFrame title="Authentication failures">
          {data?.series ? <CategoryBar data={data.series.map((s: any) => ({ t: fmtX(s.t), v: s.auth_failures }))} x="t" y="v" /> : <div className="skeleton h-[220px]" />}
        </ChartFrame>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <ChartFrame title="Threats by category">{threats.length ? <SimpleBar data={threats} x="category" y="count" color="#ef4444" horizontal /> : <Empty title="No threats in window" />}</ChartFrame>
        <ChartFrame title="Detection outcomes">{outcomes.length ? <Donut data={outcomes} /> : <Empty title="No assessments yet" />}</ChartFrame>
        <ChartFrame title="Risk score distribution">{dist.length ? <CategoryBar data={dist} x="range" y="count" /> : <div className="skeleton h-[200px]" />}</ChartFrame>
      </div>

      <ChartFrame title="Model inference latency (ms)">
        {data?.series ? <CategoryBar data={data.series.filter((s: any) => s.inference_ms != null).map((s: any) => ({ t: fmtX(s.t), v: s.inference_ms }))} x="t" y="v" height={160} /> : <Empty title="No inference samples" />}
      </ChartFrame>
    </div>
  );
}

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
function SessionsArea({ data, fmtX }: { data: any[]; fmtX: (v: any) => string }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
        <defs><linearGradient id="sess" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#06b6d4" stopOpacity={0.5} /><stop offset="100%" stopColor="#06b6d4" stopOpacity={0} /></linearGradient></defs>
        <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
        <XAxis dataKey="t" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} tickFormatter={fmtX} minTickGap={40} />
        <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} width={28} allowDecimals={false} />
        <Tooltip contentStyle={{ background: "var(--color-overlay)", border: "1px solid var(--color-border-strong)", borderRadius: 8, fontSize: 12 }} labelFormatter={fmtX} />
        <Area type="monotone" dataKey="active_sessions" name="Active sessions" stroke="#06b6d4" strokeWidth={2} fill="url(#sess)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
