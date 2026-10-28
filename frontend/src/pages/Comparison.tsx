import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { GitCompareArrows, Play, Layers, ShieldX, ShieldCheck, Zap } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import type { Scenario } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, Chip, Spinner, Empty } from "@/components/ui";
import { SimpleBar } from "@/components/charts";
import { cn } from "@/lib/utils";

export default function Comparison() {
  const { data: scns } = useQuery({ queryKey: ["scenarios"], queryFn: () => api.get<{ scenarios: Scenario[] }>("/simulation/scenarios") });
  const [scenario, setScenario] = useState("token_replay");
  const [result, setResult] = useState<any>(null);
  const [all, setAll] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const attack = (scns?.scenarios ?? []).filter((s) => s.category !== "baseline" && s.category !== "recovery");

  const run = async () => {
    setBusy(true); setAll(null);
    try { setResult(await api.post<any>("/experiment/compare", { scenario })); toast.success("Comparison complete"); }
    catch (e: any) { toast.error(e.message); }
    setBusy(false);
  };
  const runAll = async () => {
    setBusy(true); setResult(null);
    try { setAll(await api.post<any>("/experiment/compare-all")); toast.success("Ran all attack scenarios in both modes"); }
    catch (e: any) { toast.error(e.message); }
    setBusy(false);
  };

  return (
    <div>
      <PageHeader title="Experimental Comparison" icon={GitCompareArrows}
        subtitle="Run identical scenarios through conventional validation and SessionGuard; every figure comes from real runs."
        actions={<button className="btn" onClick={runAll} disabled={busy}><Layers size={15} /> Run all attacks</button>} />

      <Panel className="mb-3">
        <div className="flex flex-wrap items-center gap-2">
          <select className="input max-w-xs" value={scenario} onChange={(e) => setScenario(e.target.value)}>
            {attack.map((s) => <option key={s.key} value={s.key}>{s.name}</option>)}
          </select>
          <button className="btn btn-primary" onClick={run} disabled={busy}>{busy ? <Spinner /> : <><Play size={15} /> Compare</>}</button>
        </div>
      </Panel>

      {result && <CompareResult r={result} />}

      {all && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[["Scenarios", all.aggregate.scenarios], ["Traditional accepted attacker req", all.aggregate.traditional_accepted, "danger"],
              ["SessionGuard accepted attacker req", all.aggregate.sessionguard_accepted, "success"], ["SessionGuard contained", `${all.aggregate.sessionguard_contained}/${all.aggregate.scenarios}`, "success"]].map(([k, v, t]: any) => (
              <Panel key={k}><div className="card-title">{k}</div><div className={cn("mt-1 text-2xl font-semibold tnum", t === "danger" ? "text-red-300" : t === "success" ? "text-emerald-300" : "")}>{v}</div></Panel>
            ))}
          </div>
          <Panel title="Accepted attacker requests by scenario (lower is better)">
            <SimpleBar
              data={all.results.map((r: any) => ({ name: r.name, Traditional: r.traditional.accepted_attacker_requests, SessionGuard: r.sessionguard.accepted_attacker_requests }))}
              x="name" y="Traditional" color="#ef4444" horizontal height={280} />
            <p className="mt-2 text-xs text-[color:var(--color-faint)]">Traditional validation accepts every valid-token request; SessionGuard blocks the suspicious ones once risk crosses policy thresholds.</p>
          </Panel>
          <div className="space-y-3">{all.results.map((r: any) => <CompareResult key={r.scenario} r={r} compact />)}</div>
        </div>
      )}

      {!result && !all && !busy && <Panel><Empty icon={<GitCompareArrows size={26} />} title="No comparison yet" hint="Pick a scenario and press Compare, or run all attack scenarios at once." /></Panel>}
    </div>
  );
}

function CompareResult({ r, compact }: { r: any; compact?: boolean }) {
  const cols = [
    { k: "accepted_attacker_requests", l: "Attacker accepted", lowerBetter: true },
    { k: "blocked_attacker_requests", l: "Attacker blocked", lowerBetter: false },
    { k: "detected", l: "Detected", bool: true },
    { k: "revoked", l: "Revoked", bool: true },
    { k: "challenged", l: "Challenged", bool: true },
    { k: "peak_risk", l: "Peak risk" },
    { k: "containment_latency_s", l: "Containment (s)" },
  ];
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <Panel title={compact ? r.name : `${r.name} — traditional vs SessionGuard`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-[color:var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[color:var(--color-faint)]">
              <th className="px-3 py-2 font-medium">Metric</th>
              <th className="px-3 py-2 font-medium"><span className="flex items-center gap-1.5 text-red-300"><ShieldX size={13} /> Traditional</span></th>
              <th className="px-3 py-2 font-medium"><span className="flex items-center gap-1.5 text-emerald-300"><ShieldCheck size={13} /> SessionGuard</span></th>
            </tr></thead>
            <tbody>
              {cols.map((c) => {
                const t = r.traditional[c.k], s = r.sessionguard[c.k];
                const fmt = (v: any) => c.bool ? (v ? "yes" : "no") : v == null ? "—" : typeof v === "number" ? v.toFixed(c.k === "peak_risk" || c.k === "containment_latency_s" ? 1 : 0) : v;
                return (
                  <tr key={c.k} className="border-b border-[color:var(--color-border)]/60">
                    <td className="px-3 py-2 text-[color:var(--color-muted)]">{c.l}</td>
                    <td className="px-3 py-2 font-mono">{fmt(t)}</td>
                    <td className="px-3 py-2 font-mono font-semibold">{fmt(s)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex items-center gap-2 rounded-lg bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200 ring-1 ring-emerald-500/20">
          <Zap size={14} /> {r.verdict.sessionguard_contained ? `SessionGuard contained this attack (${r.sessionguard.blocked_attacker_requests} attacker requests blocked); traditional validation accepted ${r.traditional.accepted_attacker_requests}.`
            : "SessionGuard raised risk and monitored; traditional validation took no action."}
        </div>
      </Panel>
    </motion.div>
  );
}
