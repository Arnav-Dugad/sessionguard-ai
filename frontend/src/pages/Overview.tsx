import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, Users, ShieldAlert, Ban, Gauge, Timer, Cpu, AlertTriangle, ArrowUpRight, Wifi, WifiOff } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveEvents } from "@/lib/useLiveEvents";
import type { Overview as OverviewData } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, StatTile, BandBadge, Empty } from "@/components/ui";
import { EventFeed } from "@/components/EventFeed";
import { RiskAreaChart, StackedActivityChart, ChartFrame, Donut } from "@/components/charts";
import { fmtTime } from "@/lib/utils";

const fmtX = (t: string) => fmtTime(t);

export default function Overview() {
  const { data, isLoading } = useQuery({ queryKey: ["overview"], queryFn: () => api.get<OverviewData>("/security/overview"), refetchInterval: 4000 });
  const { data: metrics } = useQuery({ queryKey: ["metrics-overview"], queryFn: () => api.get<any>("/security/metrics?window_minutes=60&buckets=30"), refetchInterval: 6000 });
  const { events, status } = useLiveEvents(true);

  const bands = data?.band_distribution ?? {};
  const bandData = [
    { name: "Low", value: bands.low ?? 0 }, { name: "Elevated", value: bands.elevated ?? 0 },
    { name: "High", value: bands.high ?? 0 }, { name: "Critical", value: bands.critical ?? 0 },
  ].filter((b) => b.value > 0);

  return (
    <div>
      <PageHeader title="Security Operations Overview" icon={Gauge}
        subtitle="Live posture across all sessions. Every figure is computed from stored application data."
        actions={
          <span className={`chip ring-1 ${status === "open" ? "bg-emerald-500/12 text-emerald-300 ring-emerald-500/25" : "bg-slate-500/10 text-slate-300 ring-slate-500/20"}`}>
            {status === "open" ? <Wifi size={13} /> : <WifiOff size={13} />} live feed {status}
          </span>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Active sessions" value={isLoading ? "—" : data!.active_sessions} icon={<Activity size={18} />} delay={0} />
        <StatTile label="Registered users" value={isLoading ? "—" : data!.total_users} icon={<Users size={18} />} tone="cyan" delay={0.04} />
        <StatTile label="Under investigation" value={isLoading ? "—" : data!.under_investigation} sub="risk ≥ elevated" icon={<AlertTriangle size={18} />} tone="warning" delay={0.08} />
        <StatTile label="Threats detected" value={isLoading ? "—" : data!.threats_detected} sub={`${data?.threats_24h ?? 0} in 24h`} icon={<ShieldAlert size={18} />} tone="critical" delay={0.12} />
        <StatTile label="Auto-revoked" value={isLoading ? "—" : data!.auto_revoked} sub={`${data?.step_up_challenges ?? 0} step-ups`} icon={<Ban size={18} />} tone="critical" delay={0.16} />
        <StatTile label="Avg session risk" value={isLoading ? "—" : data!.avg_risk.toFixed(1)} icon={<Gauge size={18} />} tone="accent" delay={0.2} />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <StatTile label="Detection latency (p95)" value={data?.detection_latency_ms?.p95 != null ? `${data.detection_latency_ms.p95.toFixed(1)} ms` : "—"}
          sub={`mean ${data?.detection_latency_ms?.mean?.toFixed(1) ?? "—"} ms · ${data?.detection_latency_ms?.samples ?? 0} samples`} icon={<Timer size={18} />} tone="cyan" />
        <StatTile label="Model inference (median)" value={data?.inference_ms?.median != null ? `${data.inference_ms.median.toFixed(3)} ms` : "—"}
          sub={data?.model?.active_label ?? "—"} icon={<Cpu size={18} />} tone="accent" />
        <StatTile label="Events / minute" value={data?.events_per_minute ?? "—"} sub={`${data?.auth_failures_24h ?? 0} auth failures / 24h`} icon={<Activity size={18} />} tone="warning" />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 xl:grid-cols-3">
        <div className="xl:col-span-2 space-y-3">
          <ChartFrame title="Session risk over time (last hour)">
            {metrics?.series ? <RiskAreaChart data={metrics.series} fmtX={fmtX} /> : <div className="skeleton h-[220px]" />}
          </ChartFrame>
          <ChartFrame title="Normal vs suspicious activity">
            {metrics?.series ? <StackedActivityChart data={metrics.series} fmtX={fmtX} /> : <div className="skeleton h-[220px]" />}
          </ChartFrame>
        </div>

        <div className="space-y-3">
          <Panel title="Risk band distribution">
            {bandData.length ? <Donut data={bandData} /> : <Empty title="No active sessions" hint="Run a scenario in the Attack Simulation Lab to populate the console." />}
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              {(["low", "elevated", "high", "critical"] as const).map((b) => (
                <div key={b} className="flex items-center justify-between rounded-lg bg-[color:var(--color-elevated)] px-2.5 py-1.5">
                  <BandBadge band={b} /><span className="font-mono tnum">{bands[b] ?? 0}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 xl:grid-cols-3">
        <Panel className="xl:col-span-2" title="Live activity feed"
          action={<Link to="/events" className="flex items-center gap-1 text-xs text-blue-300 hover:underline">All events <ArrowUpRight size={13} /></Link>}>
          {events.length ? <div className="max-h-[420px] overflow-y-auto pr-1"><EventFeed events={events} max={40} /></div>
            : <Empty title="Waiting for events" hint="The feed updates in real time as sessions are evaluated." />}
        </Panel>
        <Panel title="Recent authentication failures"
          action={data?.model && <span className="chip bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/20">{data.model.active_label}</span>}>
          {data?.recent_auth_failures?.length ? (
            <div className="space-y-1.5">
              {data.recent_auth_failures.map((e) => (
                <div key={e.id} className="rounded-lg bg-[color:var(--color-elevated)] px-3 py-2 text-xs">
                  <div className="flex items-center justify-between"><span className="font-medium text-amber-300">{e.metadata?.username ?? e.username ?? "unknown"}</span><span className="font-mono text-[color:var(--color-faint)]">{fmtTime(e.timestamp)}</span></div>
                  <p className="mt-0.5 text-[color:var(--color-muted)]">{e.explanation}</p>
                </div>
              ))}
            </div>
          ) : <Empty title="No recent failures" />}
        </Panel>
      </div>
    </div>
  );
}
