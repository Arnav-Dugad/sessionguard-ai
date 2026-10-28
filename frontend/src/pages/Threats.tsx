import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Clock, ShieldCheck, Activity, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Incident } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, BandBadge, Chip, Empty } from "@/components/ui";
import { ContributionBars } from "@/components/RiskMeter";
import { EventFeed } from "@/components/EventFeed";
import { fmtDateTime, timeAgo, cn, SEVERITY_META } from "@/lib/utils";

const KIND_LABEL: Record<string, string> = {
  replay: "Token replay", device: "Device anomaly", network: "Network anomaly", behavior: "Behaviour anomaly",
  ml: "ML anomaly", relay: "BITM relay (synthetic)", access: "Access violation", other: "Suspicious session",
};
const STATUS_TONE: Record<string, any> = { contained: "success", revoked: "danger", challenged: "warning", open: "warning", closed: "muted" };

export default function Threats() {
  const [sel, setSel] = useState<string | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["alerts"], queryFn: () => api.get<{ incidents: Incident[] }>("/security/alerts"), refetchInterval: 5000 });
  const detail = useQuery({ queryKey: ["alert", sel], queryFn: () => api.get<any>(`/security/alerts/${sel}`), enabled: !!sel });

  const incidents = data?.incidents ?? [];

  return (
    <div>
      <PageHeader title="Threat Detection" icon={ShieldAlert}
        subtitle="Suspicious sessions grouped into incidents, each with its evidence, risk calculation and containment outcome." />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[400px_1fr]">
        <div className="space-y-2">
          {isLoading ? [...Array(5)].map((_, i) => <div key={i} className="skeleton h-24" />)
            : incidents.length === 0 ? <Panel><Empty icon={<ShieldCheck size={26} />} title="No active threats" hint="Run a scenario in the Attack Simulation Lab to generate incidents." /></Panel>
            : incidents.map((inc) => {
              const sev = SEVERITY_META[inc.severity] ?? SEVERITY_META.info;
              return (
                <button key={inc.id} onClick={() => setSel(inc.id)}
                  className={cn("w-full rounded-xl border p-3 text-left transition-all", sel === inc.id ? "border-blue-500/40 bg-blue-500/10" : "border-[color:var(--color-border)] bg-[color:var(--color-surface)] hover:border-[color:var(--color-border-strong)]",
                    inc.status === "open" && inc.severity === "critical" && "critical-ring")}>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-sm font-medium"><span className={cn("h-2 w-2 rounded-full", sev.dot)} />{KIND_LABEL[inc.kind] ?? inc.title}</span>
                    <Chip tone={STATUS_TONE[inc.status]}>{inc.status}</Chip>
                  </div>
                  <div className="mt-1.5 flex items-center gap-2 text-xs text-[color:var(--color-muted)]">
                    <span className="font-mono">{inc.id}</span><span>·</span><span>{inc.session.username}</span>
                    {inc.synthetic && <span className="chip bg-fuchsia-500/12 text-fuchsia-300 ring-1 ring-fuchsia-500/25">synthetic</span>}
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[11px] text-[color:var(--color-faint)]">
                    <span>peak risk <span className="font-mono text-[color:var(--color-ink)]">{inc.peak_risk.toFixed(0)}</span> · {inc.alert_count} alerts</span>
                    <span>{timeAgo(inc.last_seen)}</span>
                  </div>
                </button>
              );
            })}
        </div>

        <ThreatDetail detail={detail.data} loading={detail.isFetching} empty={!sel} />
      </div>
    </div>
  );
}

function ThreatDetail({ detail, loading, empty }: { detail: any; loading: boolean; empty: boolean }) {
  if (empty) return <Panel><Empty icon={<ShieldAlert size={26} />} title="Select an incident" hint="Choose an incident to see its full timeline, evidence and the exact risk calculation that drove containment." /></Panel>;
  if (loading || !detail) return <Panel><div className="space-y-2">{[...Array(8)].map((_, i) => <div key={i} className="skeleton h-5" />)}</div></Panel>;

  const pa = detail.peak_assessment;
  const o = detail.outcome;
  return (
    <div className="space-y-3">
      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="text-lg font-semibold">{KIND_LABEL[detail.kind] ?? detail.title}</h2>
            <p className="mt-0.5 text-sm text-[color:var(--color-muted)]">Session <span className="font-mono">{detail.session.id}</span> · {detail.session.username} · {detail.session.device?.label}</p>
          </div>
          <div className="flex items-center gap-2"><BandBadge band={detail.session.band} /><Chip tone={STATUS_TONE[detail.status]}>{detail.status}</Chip></div>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {[["Detected", o.detected_at ? fmtDateTime(o.detected_at) : "—"], ["Contained", o.contained_at ? fmtDateTime(o.contained_at) : "—"],
            ["Time to contain", o.time_to_contain_s != null ? `${o.time_to_contain_s.toFixed(1)}s` : "—"], ["Denied after", o.denied_after_containment]].map(([k, v]) => (
            <div key={k as string} className="rounded-lg bg-[color:var(--color-elevated)] px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-[color:var(--color-faint)]">{k}</div><div className="mt-0.5 font-mono text-sm">{v}</div>
            </div>
          ))}
        </div>
      </Panel>

      {pa && (
        <Panel title={`Risk calculation (peak ${pa.score.toFixed(1)})`} action={<Chip tone="cyan">{pa.model}</Chip>}>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-[color:var(--color-muted)]">
            <Chip tone="muted">instant {pa.instant.toFixed(1)}</Chip>
            {pa.probability != null && <Chip tone="cyan">ML prob {pa.probability.toFixed(3)}</Chip>}
            <Chip tone={pa.decision === "revoke" ? "danger" : "warning"}>decision: {pa.decision}</Chip>
            <span className="font-mono">inference {pa.inference_ms?.toFixed(3)} ms</span>
          </div>
          <ContributionBars contributions={pa.contributions} />
        </Panel>
      )}

      <Panel title="Incident timeline"><div className="max-h-80 overflow-y-auto pr-1"><EventFeed events={detail.timeline} max={100} /></div></Panel>
    </div>
  );
}
