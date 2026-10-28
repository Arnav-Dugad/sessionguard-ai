import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Presentation, ChevronLeft, ChevronRight, Play, Pause, RotateCcw, Check } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { StepResult } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, Chip, Spinner, BandBadge } from "@/components/ui";
import { RiskMeter } from "@/components/RiskMeter";
import { EventFeed } from "@/components/EventFeed";
import { cn } from "@/lib/utils";

const SCENARIO = "token_replay";
const NARRATIVE = [
  "A legitimate user signs in. The server issues a random token and records a trust baseline.",
  "The user browses normally — telemetry is collected and risk stays Low.",
  "The user continues; behaviour is unremarkable.",
  "The user opens a document — still the trusted device and network.",
  "The user performs a sensitive export — allowed without friction at Low risk.",
  "An attacker obtains the valid token (modelled by the harness copying the cookie).",
  "The attacker replays the token from a different device and region — conventional checks accept it.",
  "The legitimate user is still active, so the token now alternates between two contexts.",
  "The attacker probes further; concurrency evidence and the ML model push risk up.",
  "The attacker attempts a sensitive action — the session is challenged or contained.",
  "The attacker retries the token after containment — the backend rejects it (401).",
];

export default function PresentationMode() {
  const [runId, setRunId] = useState<number | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [idx, setIdx] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [done, setDone] = useState(false);
  const timer = useRef<number | null>(null);

  const reset = async () => {
    if (timer.current) clearTimeout(timer.current);
    setPlaying(false);
    await api.post("/simulation/reset").catch(() => {});
    setRunId(null); setSteps([]); setIdx(-1); setDone(false);
  };

  const advance = async () => {
    setBusy(true);
    let id = runId;
    try {
      if (id == null) { id = (await api.post<{ run_id: number }>("/simulation/start", { scenario: SCENARIO, mode: "sessionguard" })).run_id; setRunId(id); }
      const r = await api.post<StepResult>("/simulation/step", { run_id: id });
      setSteps((p) => [...p, r]); setIdx((i) => i + 1);
      if (r.final || !r.has_next) { setDone(true); setPlaying(false); }
    } catch (e: any) { toast.error(e.message); setPlaying(false); }
    setBusy(false);
  };

  useEffect(() => {
    if (playing && !done && !busy) timer.current = window.setTimeout(advance, 1600);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [playing, idx, done, busy]);

  const cur = steps[idx];
  const risk = steps.slice(0, idx + 1).flatMap((s) => s.exchanges).filter((e) => e.risk != null).slice(-1)[0]?.risk ?? 0;
  const events = steps.slice(0, idx + 1).flatMap((s) => s.events);
  const total = NARRATIVE.length;

  return (
    <div>
      <PageHeader title="Presentation Mode" icon={Presentation}
        subtitle="A guided, five-minute walkthrough of the full attack-and-defense story. Every value is produced by real backend requests." />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <button className="btn" onClick={() => { setIdx((i) => Math.max(0, i - 1)); }} disabled={idx <= 0}><ChevronLeft size={15} /> Previous</button>
        <button className="btn btn-primary" onClick={advance} disabled={busy || done}>{busy ? <Spinner /> : <><ChevronRight size={15} /> Next step</>}</button>
        <button className="btn" onClick={() => setPlaying((p) => !p)} disabled={done}>{playing ? <><Pause size={15} /> Pause</> : <><Play size={15} /> Run full</>}</button>
        <button className="btn btn-ghost" onClick={reset}><RotateCcw size={15} /> Reset</button>
        <div className="ml-auto flex items-center gap-2 text-xs text-[color:var(--color-muted)]">
          <span className="font-mono">{Math.max(0, idx + 1)}/{total}</span>
          <div className="h-1.5 w-40 overflow-hidden rounded-full bg-[color:var(--color-elevated)]"><motion.div className="h-full bg-blue-500" animate={{ width: `${((idx + 1) / total) * 100}%` }} /></div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_320px]">
        <div className="space-y-3">
          {/* Stepper */}
          <Panel>
            <div className="flex flex-wrap gap-1.5">
              {NARRATIVE.map((_, i) => (
                <div key={i} className={cn("flex h-7 w-7 items-center justify-center rounded-full text-[11px] font-semibold transition-colors",
                  i < idx ? "bg-emerald-500/20 text-emerald-300" : i === idx ? "bg-blue-500 text-white" : "bg-[color:var(--color-elevated)] text-[color:var(--color-faint)]")}>
                  {i < idx ? <Check size={13} /> : i + 1}
                </div>
              ))}
            </div>
          </Panel>

          {/* Narrative + live request */}
          <AnimatePresence mode="wait">
            <motion.div key={idx} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <Panel>
                {idx < 0 ? (
                  <div className="py-10 text-center">
                    <Presentation size={32} className="mx-auto text-blue-300" />
                    <h2 className="mt-3 text-lg font-semibold">Session hijacking: detection & containment</h2>
                    <p className="mx-auto mt-1 max-w-md text-sm text-[color:var(--color-muted)]">Press <b>Next step</b> to begin, or <b>Run full</b> to play the whole story automatically. It runs the controlled token-replay scenario end to end.</p>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <h2 className="text-lg font-semibold">Step {idx + 1}. {cur?.title}</h2>
                      {cur?.malicious ? <Chip tone="danger">attacker</Chip> : <Chip tone="success">legitimate</Chip>}
                    </div>
                    <p className="mt-2 text-[15px] leading-relaxed text-[color:var(--color-ink)]">{NARRATIVE[idx]}</p>
                    <p className="mt-2 text-sm text-[color:var(--color-muted)]">{cur?.explanation}</p>

                    {cur?.exchanges?.length ? (
                      <div className="mt-3 space-y-2">
                        {cur.exchanges.map((ex, i) => (
                          <div key={i} className="flex items-center gap-3 rounded-lg bg-[color:var(--color-bg)] px-3 py-2 font-mono text-xs">
                            <span className="rounded bg-black/40 px-1.5 py-0.5">{ex.method}</span>
                            <span className="truncate text-[color:var(--color-muted)]">{ex.path}</span>
                            <span className={cn("ml-auto rounded px-1.5 py-0.5", ex.ok ? "bg-emerald-500/15 text-emerald-300" : "bg-red-500/15 text-red-300")}>{ex.status}</span>
                            {ex.decision && ex.decision !== "allow" && <span className="text-orange-300">{ex.decision}</span>}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </>
                )}
              </Panel>
            </motion.div>
          </AnimatePresence>

          {done && (
            <Panel className="border-emerald-500/30 bg-emerald-500/[0.05]">
              <div className="flex items-center gap-2 text-emerald-300"><Check size={18} /> <span className="font-semibold">Containment confirmed</span></div>
              <p className="mt-1 text-sm text-[color:var(--color-muted)]">The replayed token was accepted by conventional validation but SessionGuard detected the anomalous reuse, revoked the session server-side, and the retried token was rejected with 401. The entire sequence used real backend state transitions.</p>
            </Panel>
          )}
        </div>

        <div className="space-y-3">
          <Panel title="Live session risk"><div className="flex justify-center py-2"><RiskMeter value={risk} size={200} /></div>
            <div className="flex justify-center"><BandBadge band={risk >= 75 ? "critical" : risk >= 50 ? "high" : risk >= 25 ? "elevated" : "low"} /></div>
          </Panel>
          <Panel title="Security events"><div className="max-h-[320px] overflow-y-auto pr-1">{events.length ? <EventFeed events={[...events].reverse()} /> : <p className="text-xs text-[color:var(--color-faint)]">Events appear as the story unfolds.</p>}</div></Panel>
        </div>
      </div>
    </div>
  );
}
