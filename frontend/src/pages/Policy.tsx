import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SlidersHorizontal, Save, RotateCcw, Info } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, Toggle, BandBadge, Chip } from "@/components/ui";

export default function PolicyPage() {
  const { data, refetch } = useQuery({ queryKey: ["policy"], queryFn: () => api.get<any>("/policy") });
  const [draft, setDraft] = useState<Policy | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => { if (data?.policy && !draft) setDraft(structuredClone(data.policy)); }, [data]);

  if (!draft || !data) return <div className="space-y-3">{[...Array(4)].map((_, i) => <div key={i} className="skeleton h-24" />)}</div>;

  const dirty = JSON.stringify(draft) !== JSON.stringify(data.policy);
  const set = (patch: Partial<Policy>) => setDraft((d) => ({ ...d!, ...patch }));
  const setWeight = (k: string, v: number) => setDraft((d) => ({ ...d!, weights: { ...d!.weights, [k]: v } }));
  const setThresh = (k: string, v: number) => setDraft((d) => ({ ...d!, thresholds: { ...d!.thresholds, [k]: v } }));

  const save = async () => {
    setSaving(true);
    try { await api.put("/policy", draft); toast.success("Policy updated — applies to the next request"); await refetch(); }
    catch (e: any) { toast.error(e.fields?.[0]?.message ?? e.message); }
    setSaving(false);
  };
  const reset = async () => { await api.post("/policy/reset"); const r = await refetch(); setDraft(structuredClone(r.data!.policy)); toast.success("Reset to defaults"); };

  const help = data.evidence_weights_help ?? {};

  return (
    <div>
      <PageHeader title="Zero-Trust Policy Manager" icon={SlidersHorizontal}
        subtitle="Tune evidence weights, risk thresholds and containment actions. Changes take effect on the next evaluated request."
        actions={
          <div className="flex items-center gap-2">
            <button className="btn btn-ghost" onClick={reset}><RotateCcw size={14} /> Defaults</button>
            <button className="btn btn-primary" onClick={save} disabled={!dirty || saving}><Save size={14} /> {saving ? "Saving…" : dirty ? "Save changes" : "Saved"}</button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Panel title="Evidence weights" action={<Chip tone="muted">0–100</Chip>}>
          <p className="mb-3 text-xs text-[color:var(--color-faint)]">Each weight caps how much an evidence source can contribute. Correlated signals are grouped so they never double-count; fusion is noisy-OR, so the score stays in 0–100.</p>
          <div className="space-y-3">
            {Object.entries(draft.weights).map(([k, v]) => (
              <div key={k}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="capitalize">{k}</span><span className="font-mono font-semibold">{v}</span>
                </div>
                <input type="range" min={0} max={100} value={v} onChange={(e) => setWeight(k, +e.target.value)} className="w-full accent-blue-500" />
                {help[k] && <p className="mt-0.5 text-[10px] text-[color:var(--color-faint)]">{help[k]}</p>}
              </div>
            ))}
          </div>
        </Panel>

        <div className="space-y-3">
          <Panel title="Risk thresholds">
            <div className="space-y-3">
              {(["elevated", "high", "critical"] as const).map((k) => (
                <div key={k}>
                  <div className="mb-1 flex items-center justify-between text-xs"><span className="flex items-center gap-2"><BandBadge band={k} /></span><span className="font-mono font-semibold">{(draft.thresholds as any)[k]}</span></div>
                  <input type="range" min={1} max={100} value={(draft.thresholds as any)[k]} onChange={(e) => setThresh(k, +e.target.value)} className="w-full accent-blue-500" />
                </div>
              ))}
            </div>
            <div className="mt-3 h-3 overflow-hidden rounded-full flex">
              <div style={{ width: `${draft.thresholds.elevated}%` }} className="bg-emerald-500" />
              <div style={{ width: `${draft.thresholds.high - draft.thresholds.elevated}%` }} className="bg-amber-500" />
              <div style={{ width: `${draft.thresholds.critical - draft.thresholds.high}%` }} className="bg-orange-500" />
              <div style={{ width: `${100 - draft.thresholds.critical}%` }} className="bg-red-500" />
            </div>
          </Panel>

          <Panel title="Containment behaviour">
            <div className="space-y-3 text-sm">
              <label className="flex items-center justify-between">
                <span>Enforcement</span>
                <div className="flex overflow-hidden rounded-lg border border-[color:var(--color-border-strong)]">
                  {(["enforce", "monitor"] as const).map((m) => <button key={m} onClick={() => set({ enforcement: m })} className={`px-3 py-1 text-xs ${draft.enforcement === m ? "bg-blue-500 text-white" : "bg-[color:var(--color-elevated)] text-[color:var(--color-muted)]"}`}>{m}</button>)}
                </div>
              </label>
              <label className="flex items-center justify-between">
                <span>Critical action</span>
                <div className="flex overflow-hidden rounded-lg border border-[color:var(--color-border-strong)]">
                  {(["revoke", "deny_sensitive"] as const).map((m) => <button key={m} onClick={() => set({ critical_action: m })} className={`px-3 py-1 text-xs ${draft.critical_action === m ? "bg-blue-500 text-white" : "bg-[color:var(--color-elevated)] text-[color:var(--color-muted)]"}`}>{m.replace("_", " ")}</button>)}
                </div>
              </label>
              <label className="flex items-center justify-between"><span>Step-up on context change</span><Toggle checked={draft.step_up_on_context_change} onChange={(v) => set({ step_up_on_context_change: v })} /></label>
              <label className="flex items-center justify-between"><span>ML scoring enabled</span><Toggle checked={draft.ml_enabled} onChange={(v) => set({ ml_enabled: v })} /></label>
              <div>
                <div className="mb-1 flex items-center justify-between text-xs"><span>ML operating floor</span><span className="font-mono">{draft.ml_floor.toFixed(2)}</span></div>
                <input type="range" min={0} max={0.9} step={0.05} value={draft.ml_floor} onChange={(e) => set({ ml_floor: +e.target.value })} className="w-full accent-blue-500" />
                <p className="mt-0.5 text-[10px] text-[color:var(--color-faint)]">Probabilities below the floor contribute no risk — suppresses the model's benign baseline offset.</p>
              </div>
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Band → action matrix" className="mt-3">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-[color:var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[color:var(--color-faint)]">
              {["Band", "Non-sensitive request", "Sensitive request", "Monitoring"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}
            </tr></thead>
            <tbody>
              {Object.entries(data.band_matrix).map(([band, m]: any) => (
                <tr key={band} className="border-b border-[color:var(--color-border)]/60">
                  <td className="px-3 py-2.5"><BandBadge band={band} /></td>
                  <td className="px-3 py-2.5 text-[color:var(--color-muted)]">{m.non_sensitive}</td>
                  <td className="px-3 py-2.5 text-[color:var(--color-muted)]">{m.sensitive}</td>
                  <td className="px-3 py-2.5 text-[color:var(--color-muted)]">{m.monitoring}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 flex items-start gap-1.5 text-xs text-[color:var(--color-faint)]"><Info size={13} className="mt-0.5 shrink-0" /> Security decisions never trust client-supplied risk values; the server recomputes risk on every request.</p>
      </Panel>
    </div>
  );
}
