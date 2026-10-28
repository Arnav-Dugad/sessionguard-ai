import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, Pause, Play, Search, Filter } from "lucide-react";
import { api } from "@/lib/api";
import type { SecurityEvent } from "@/lib/types";
import { useLiveEvents } from "@/lib/useLiveEvents";
import { PageHeader } from "@/components/Layout";
import { Panel, Toggle, Chip, Empty } from "@/components/ui";
import { EventRow } from "@/components/EventFeed";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export default function Events() {
  const [paused, setPaused] = useState(false);
  const [minSev, setMinSev] = useState<string>("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<SecurityEvent | null>(null);
  const { events: live, status, clear } = useLiveEvents(!paused);

  // When paused, fall back to a REST snapshot so the page is never empty.
  const snapshot = useQuery({
    queryKey: ["events-snapshot"], enabled: paused,
    queryFn: () => api.get<{ events: SecurityEvent[] }>("/security/events?limit=200&include_activity=true"),
  });

  const source = paused ? snapshot.data?.events ?? [] : live;
  const filtered = useMemo(() => {
    const order: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    return source.filter((e) =>
      (!minSev || order[e.severity] >= order[minSev]) &&
      (!q || e.event_type.toLowerCase().includes(q.toLowerCase()) || e.explanation.toLowerCase().includes(q.toLowerCase()) || (e.session_ref ?? "").includes(q)));
  }, [source, minSev, q]);

  return (
    <div>
      <PageHeader title="Live Security Events" icon={Activity}
        subtitle="Real-time stream over a WebSocket authorised by the admin session. Pause to inspect a snapshot."
        actions={
          <div className="flex items-center gap-2 text-xs">
            <span className={`chip ring-1 ${status === "open" && !paused ? "bg-emerald-500/12 text-emerald-300 ring-emerald-500/25" : "bg-slate-500/10 text-slate-300 ring-slate-500/20"}`}>
              <span className={status === "open" && !paused ? "live-dot" : "h-2 w-2 rounded-full bg-slate-400"} /> {paused ? "paused" : status}
            </span>
            <button className="btn" onClick={() => setPaused((p) => !p)}>{paused ? <><Play size={14} /> Resume</> : <><Pause size={14} /> Pause</>}</button>
            {!paused && <button className="btn btn-ghost" onClick={clear}>Clear</button>}
          </div>
        }
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative max-w-xs flex-1">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-faint)]" />
          <input className="input pl-9" placeholder="Filter events…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-[color:var(--color-border-strong)] p-0.5">
          <Filter size={13} className="ml-1.5 text-[color:var(--color-faint)]" />
          {["", ...SEVERITIES].map((s) => (
            <button key={s || "all"} onClick={() => setMinSev(s)}
              className={`rounded px-2 py-1 text-xs capitalize ${minSev === s ? "bg-blue-500 text-white" : "text-[color:var(--color-muted)] hover:bg-white/5"}`}>{s || "all"}</button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_360px]">
        <Panel className="!p-2">
          <div className="max-h-[70vh] overflow-y-auto">
            {filtered.length ? filtered.map((e) => <EventRow key={e.id} ev={e} onClick={() => setSel(e)} />)
              : <Empty icon={<Activity size={24} />} title={paused ? "No events match" : "Waiting for events"} hint="Trigger activity in the Lab or sign in from the portal." />}
          </div>
        </Panel>
        <Panel title="Event detail">
          {sel ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2"><Chip tone="accent">{sel.event_type}</Chip>{sel.synthetic && <Chip tone="danger">synthetic</Chip>}</div>
              <p className="text-[color:var(--color-muted)]">{sel.explanation}</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[["Severity", sel.severity], ["Category", sel.category], ["Detection", sel.detection_method], ["Action", sel.action_taken],
                  ["Risk before", sel.risk_before.toFixed(1)], ["Risk after", sel.risk_after.toFixed(1)], ["Session", sel.session_ref], ["User", sel.username]].map(([k, v]) => (
                  <div key={k as string} className="rounded-lg bg-[color:var(--color-elevated)] px-2.5 py-1.5"><div className="text-[10px] uppercase tracking-wider text-[color:var(--color-faint)]">{k}</div><div className="mt-0.5 truncate font-mono">{String(v ?? "—")}</div></div>
                ))}
              </div>
              {sel.metadata && Object.keys(sel.metadata).length > 0 && (
                <div><h4 className="card-title mb-1">Metadata</h4>
                  <pre className="max-h-56 overflow-auto rounded-lg bg-[color:var(--color-bg)] p-2 font-mono text-[10px] text-[color:var(--color-muted)]">{JSON.stringify(sel.metadata, null, 2)}</pre></div>
              )}
            </div>
          ) : <Empty title="Select an event" hint="Click any row to see its full payload — no token secrets are ever shown." />}
        </Panel>
      </div>
    </div>
  );
}
