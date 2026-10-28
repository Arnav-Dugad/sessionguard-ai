import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import {
  FlaskConical, Play, SkipForward, RotateCcw, FastForward, ChevronRight, ArrowRight,
  Radio, Cpu, Gauge, ShieldBan, Copy, Server, Monitor,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Exchange, Scenario, StepResult } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, BandBadge, Chip, Spinner, Empty } from "@/components/ui";
import { EventFeed } from "@/components/EventFeed";
import { RiskMeter } from "@/components/RiskMeter";
import { cn } from "@/lib/utils";

const THREAT_TONE: Record<string, string> = {
  none: "success", low: "cyan", medium: "warning", high: "warning", critical: "danger",
};
const STAGES = [
  { key: "clients", label: "Clients", icon: Monitor }, { key: "telemetry", label: "Telemetry", icon: Radio },
  { key: "ml", label: "ML Detection", icon: Cpu }, { key: "risk", label: "Risk Scoring", icon: Gauge },
  { key: "containment", label: "Containment", icon: ShieldBan },
];

function StatusPill({ status, ok }: { status: number; ok: boolean }) {
  const tone = ok ? "text-emerald-300 bg-emerald-500/12 ring-emerald-500/25" : status === 401 || status >= 500 ? "text-red-300 bg-red-500/12 ring-red-500/25" : "text-orange-300 bg-orange-500/12 ring-orange-500/25";
  return <span className={cn("chip font-mono ring-1", tone)}>{status}</span>;
}

function ExchangeCard({ ex }: { ex: Exchange }) {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}
      className={cn("rounded-lg border p-3", ex.malicious ? "border-red-500/30 bg-red-500/[0.04]" : "border-[color:var(--color-border)] bg-[color:var(--color-elevated)]")}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-xs">
          <span className={cn("grid h-6 w-6 place-items-center rounded", ex.role === "adversary" ? "bg-red-500/15 text-red-300" : "bg-blue-500/15 text-blue-300")}>
            {ex.role === "adversary" ? <Server size={13} /> : <Monitor size={13} />}
          </span>
          <span className="font-medium">{ex.client_label}</span>
        </span>
        <StatusPill status={ex.status} ok={ex.ok} />
      </div>
      <div className="mt-2 flex items-center gap-2 font-mono text-[11px] text-[color:var(--color-muted)]">
        <span className="rounded bg-black/30 px-1.5 py-0.5">{ex.method}</span>
        <span className="truncate">{ex.path}</span>
      </div>
      {ex.note && <p className="mt-2 flex items-center gap-1.5 text-[11px] text-amber-300"><Copy size={12} /> {ex.note}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {ex.risk != null && <Chip tone="muted">risk <span className="ml-1 font-mono">{ex.risk.toFixed(1)}</span></Chip>}
        {ex.band && ex.band !== "n/a" && <BandBadge band={ex.band} />}
        {ex.decision && ex.decision !== "allow" && <Chip tone={ex.decision === "revoke" ? "danger" : "warning"}>{ex.decision}</Chip>}
        <span className="ml-auto font-mono text-[10px] text-[color:var(--color-faint)]">{ex.latency_ms.toFixed(1)} ms</span>
      </div>
    </motion.div>
  );
}

export default function Lab() {
  const { data } = useQuery({ queryKey: ["scenarios"], queryFn: () => api.get<{ scenarios: Scenario[] }>("/simulation/scenarios") });
  const [selected, setSelected] = useState<string>("token_replay");
  const [mode, setMode] = useState<"sessionguard" | "traditional">("sessionguard");
  const [runId, setRunId] = useState<number | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [cursor, setCursor] = useState(0);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);

  const scenario = data?.scenarios.find((s) => s.key === selected);
  const latest = steps[steps.length - 1];
  const risk = latest?.exchanges?.filter((e) => e.risk != null).slice(-1)[0]?.risk ?? (done ? steps.flatMap((s) => s.exchanges).filter((e) => e.risk != null).slice(-1)[0]?.risk : 0) ?? 0;
  const allEvents = steps.flatMap((s) => s.events);
  const activeStage = latest ? (latest.exchanges.some((e) => e.decision === "revoke") ? "containment" : latest.exchanges.some((e) => e.risk != null) ? "risk" : latest.action === "note" ? "clients" : "telemetry") : "clients";

  useEffect(() => { feedRef.current?.scrollTo({ top: 0 }); }, [steps.length]);

  const reset = async (silent = false) => {
    await api.post("/simulation/reset").catch(() => {});
    setRunId(null); setSteps([]); setCursor(0); setDone(false);
    if (!silent) toast.success("Lab reset — all lab sessions revoked");
  };

  const start = async () => {
    setBusy(true);
    await reset(true);
    try {
      const r = await api.post<{ run_id: number }>("/simulation/start", { scenario: selected, mode });
      setRunId(r.run_id);
      toast.info(`Started “${scenario?.name}” (${mode})`);
    } catch (e: any) { toast.error(e.message ?? "Failed to start"); }
    setBusy(false);
  };

  const step = async (id = runId) => {
    if (id == null) { await start(); return; }
    setBusy(true);
    try {
      const r = await api.post<StepResult>("/simulation/step", { run_id: id });
      setSteps((p) => [...p, r]);
      setCursor((c) => c + 1);
      if (r.final || !r.has_next) { setDone(true); if (r.final) toast.success(`Scenario complete — ${r.final.summary.outcome.replace(/_/g, " ")}`); }
    } catch (e: any) { toast.error(e.message ?? "Step failed"); }
    setBusy(false);
  };

  const runAll = async () => {
    setBusy(true);
    await reset(true);
    try {
      const r = await api.post<{ steps: StepResult[]; final: any }>("/simulation/run-all", { scenario: selected, mode });
      setRunId(r.final.run_id); setSteps(r.steps); setCursor(r.steps.length); setDone(true);
      toast.success(`Completed — ${r.final.summary.outcome.replace(/_/g, " ")}`);
    } catch (e: any) { toast.error(e.message ?? "Run failed"); }
    setBusy(false);
  };

  const progress = scenario ? Math.round((cursor / scenario.step_count) * 100) : 0;

  return (
    <div>
      <PageHeader title="Attack Simulation Lab" icon={FlaskConical}
        subtitle="Reproduce controlled session-hijacking scenarios against the app's own synthetic sessions. Every request is real and travels the full pipeline."
        actions={
          <div className="flex items-center gap-2">
            <div className="flex overflow-hidden rounded-lg border border-[color:var(--color-border-strong)]">
              {(["sessionguard", "traditional"] as const).map((m) => (
                <button key={m} onClick={() => setMode(m)} disabled={busy || (runId != null && !done)}
                  className={cn("px-3 py-1.5 text-xs font-medium transition-colors", mode === m ? "bg-blue-500 text-white" : "bg-[color:var(--color-elevated)] text-[color:var(--color-muted)]")}>
                  {m === "sessionguard" ? "SessionGuard" : "Traditional"}
                </button>
              ))}
            </div>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_1fr]">
        {/* Scenario picker */}
        <div className="space-y-2">
          <h3 className="card-title px-1">Scenarios</h3>
          <div className="space-y-1.5">
            {data?.scenarios.map((s) => (
              <button key={s.key} onClick={() => { if (!busy) { setSelected(s.key); reset(true); } }}
                className={cn("w-full rounded-lg border p-3 text-left transition-all",
                  selected === s.key ? "border-blue-500/40 bg-blue-500/10" : "border-[color:var(--color-border)] bg-[color:var(--color-surface)] hover:border-[color:var(--color-border-strong)]")}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{s.name}</span>
                  <Chip tone={THREAT_TONE[s.threat_level] as any}>{s.threat_level}</Chip>
                </div>
                <p className="mt-1 line-clamp-2 text-[11px] text-[color:var(--color-faint)]">{s.tagline}</p>
                <div className="mt-1.5 flex gap-1">{s.rq.map((r) => <span key={r} className="chip bg-white/5 text-[10px] ring-1 ring-[color:var(--color-border)]">{r}</span>)}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Main stage */}
        <div className="space-y-3">
          {scenario && (
            <Panel>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="max-w-2xl">
                  <h2 className="text-lg font-semibold">{scenario.name}</h2>
                  <p className="mt-1 text-sm text-[color:var(--color-muted)]">{scenario.summary}</p>
                  <p className="mt-2 text-xs text-[color:var(--color-faint)]"><span className="text-[color:var(--color-muted)]">Teaches:</span> {scenario.teaches}</p>
                </div>
              </div>

              {/* Controls */}
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <button className="btn btn-primary" onClick={() => step()} disabled={busy || done}>
                  {busy ? <Spinner /> : runId == null ? <><Play size={15} /> Start</> : <><SkipForward size={15} /> Next step</>}
                </button>
                <button className="btn" onClick={runAll} disabled={busy}><FastForward size={15} /> Run full</button>
                <button className="btn btn-ghost" onClick={() => reset()} disabled={busy}><RotateCcw size={15} /> Reset</button>
                <div className="ml-auto flex items-center gap-2 text-xs text-[color:var(--color-muted)]">
                  <span className="font-mono">{cursor}/{scenario.step_count}</span>
                  <div className="h-1.5 w-28 overflow-hidden rounded-full bg-[color:var(--color-elevated)]">
                    <motion.div className="h-full bg-blue-500" animate={{ width: `${progress}%` }} transition={{ ease: [0.16, 1, 0.3, 1] }} />
                  </div>
                </div>
              </div>

              {/* Pipeline stages */}
              <div className="mt-4 flex items-center gap-1 overflow-x-auto pb-1">
                {STAGES.map((st, i) => {
                  const active = st.key === activeStage && !done;
                  const contained = done && st.key === "containment";
                  return (
                    <div key={st.key} className="flex items-center">
                      <div className={cn("flex items-center gap-2 rounded-lg border px-3 py-2 transition-all",
                        active ? "border-blue-500/50 bg-blue-500/10 shadow-[var(--shadow-glow)]" : contained ? "border-emerald-500/40 bg-emerald-500/10" : "border-[color:var(--color-border)] bg-[color:var(--color-elevated)]")}>
                        <st.icon size={15} className={active ? "text-blue-300" : contained ? "text-emerald-300" : "text-[color:var(--color-faint)]"} />
                        <span className="whitespace-nowrap text-xs font-medium">{st.label}</span>
                        {active && <span className="live-dot" />}
                      </div>
                      {i < STAGES.length - 1 && <ChevronRight size={14} className="mx-0.5 shrink-0 text-[color:var(--color-faint)]" />}
                    </div>
                  );
                })}
              </div>
            </Panel>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_280px]">
            {/* Step detail + exchanges */}
            <div className="space-y-3">
              {latest ? (
                <Panel title={`Step ${latest.index + 1}: ${latest.title}`}
                  action={latest.malicious ? <Chip tone="danger">attacker action</Chip> : <Chip tone="success">legitimate</Chip>}>
                  <p className="text-sm text-[color:var(--color-muted)]">{latest.explanation}</p>
                  {latest.expect && <p className="mt-2 flex items-center gap-1.5 text-xs text-[color:var(--color-faint)]"><ArrowRight size={13} /> Expected: {latest.expect}</p>}
                  <div className="mt-3 space-y-2">
                    <AnimatePresence>{latest.exchanges.map((ex, i) => <ExchangeCard key={i} ex={ex} />)}</AnimatePresence>
                  </div>
                  {latest.events.length > 0 && (
                    <div className="mt-3 border-t border-[color:var(--color-border)] pt-3">
                      <h4 className="card-title mb-2">Security events from this step</h4>
                      <EventFeed events={latest.events} />
                    </div>
                  )}
                </Panel>
              ) : (
                <Panel><Empty icon={<FlaskConical size={28} />} title="Ready to run" hint="Press Start to advance one step at a time, or Run full to execute the whole scenario. Switch to Traditional mode to see conventional validation accept the same requests." /></Panel>
              )}

              {done && latest?.final && (
                <Panel title="Scenario outcome">
                  <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                    {[
                      ["Outcome", latest.final.summary.outcome.replace(/_/g, " ")],
                      ["Peak risk", latest.final.summary.peak_risk.toFixed(1)],
                      ["Attacker accepted", latest.final.summary.attacker_accepted],
                      ["Attacker blocked", latest.final.summary.attacker_blocked],
                      ["Detected", latest.final.summary.detected ? "yes" : "no"],
                      ["Revoked", latest.final.summary.revoked ? "yes" : "no"],
                      ["Containment", latest.final.summary.containment_latency_s != null ? `${latest.final.summary.containment_latency_s}s (sim)` : "—"],
                      ["Pipeline time", latest.final.summary.detection_wall_ms != null ? `${latest.final.summary.detection_wall_ms}ms` : "—"],
                    ].map(([k, v]) => (
                      <div key={k as string} className="rounded-lg bg-[color:var(--color-elevated)] px-3 py-2">
                        <div className="text-[10px] uppercase tracking-wider text-[color:var(--color-faint)]">{k}</div>
                        <div className="mt-0.5 font-mono font-semibold">{v}</div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </div>

            {/* Risk meter + running feed */}
            <div className="space-y-3">
              <Panel title="Session risk">
                <div className="flex justify-center py-2"><RiskMeter value={mode === "traditional" ? 0 : risk} size={200} /></div>
                {mode === "traditional" && <p className="text-center text-[11px] text-[color:var(--color-faint)]">Traditional mode performs no risk scoring.</p>}
              </Panel>
              <Panel title="All events this run">
                <div ref={feedRef} className="max-h-[300px] overflow-y-auto pr-1">
                  {allEvents.length ? <EventFeed events={[...allEvents].reverse()} /> : <p className="text-xs text-[color:var(--color-faint)]">No events yet.</p>}
                </div>
              </Panel>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
