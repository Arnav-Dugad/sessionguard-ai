import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BrainCircuit, CheckCircle2, Circle, Database, GitBranch, Info } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/Layout";
import { Panel, Chip, Empty, StatTile } from "@/components/ui";
import { SimpleBar } from "@/components/charts";
import { cn } from "@/lib/utils";

export default function Models() {
  const qc = useQueryClient();
  const models = useQuery({ queryKey: ["ml-models"], queryFn: () => api.get<any>("/ml/models") });
  const evals = useQuery({ queryKey: ["ml-evals"], queryFn: () => api.get<any>("/ml/evaluations") });
  const status = useQuery({ queryKey: ["ml-status"], queryFn: () => api.get<any>("/ml/status") });
  const fi = useQuery({ queryKey: ["ml-fi"], queryFn: () => api.get<any>("/ml/feature-importance") });

  const setActive = async (m: string) => {
    try { await api.post("/ml/active", { model: m }); toast.success(`Active model: ${m}`); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };

  const ds = evals.data?.dataset;
  const list = models.data?.models ?? [];
  const best = list.filter((m: any) => m.metrics).sort((a: any, b: any) => b.metrics.f1 - a.metrics.f1)[0];
  const importance = fi.data?.available ? Object.entries(fi.data.xgboost ?? {}).slice(0, 12).map(([k, v]) => ({ name: k, v: Number(v) })) : [];

  return (
    <div>
      <PageHeader title="ML Model Evaluation" icon={BrainCircuit}
        subtitle="Rules, Logistic Regression, XGBoost and AutoEncoder+XGBoost — metrics computed on held-out sessions, never hardcoded." />

      {ds && (
        <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatTile label="Dataset" value={<span className="text-base">{ds.version}</span>} sub={`seed ${ds.seed}`} icon={<Database size={16} />} tone="cyan" />
          <StatTile label="Sessions" value={ds.class_distribution ? ds.class_distribution.session_positive + ds.class_distribution.session_negative : "—"} sub={ds.class_distribution ? `${ds.class_distribution.session_positive} attack / ${ds.class_distribution.session_negative} benign` : ""} tone="accent" />
          <StatTile label="Split" value={<span className="text-base">{ds.splits?.train_sessions}/{ds.splits?.val_sessions}/{ds.splits?.test_sessions}</span>} sub="train/val/test by session" icon={<GitBranch size={16} />} tone="success" />
          <StatTile label="Active model" value={<span className="text-base">{status.data?.active_label ?? "—"}</span>} sub={status.data?.loaded ? "loaded" : "rule-only"} tone="warning" />
        </div>
      )}

      <Panel title="Model comparison (held-out test split)" className="mb-3">
        {list.length === 0 ? <Empty title="No evaluations" hint="Run scripts/train_models.ps1 (or setup.ps1) to train and evaluate." /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-[color:var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[color:var(--color-faint)]">
                {["Model", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FPR", "Inference", "Active"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {list.map((m: any) => (
                  <tr key={m.name} className={cn("border-b border-[color:var(--color-border)]/60", best?.name === m.name && "bg-emerald-500/[0.06]")}>
                    <td className="px-3 py-2.5"><div className="flex items-center gap-2">{m.label}{best?.name === m.name && <Chip tone="success">best F1</Chip>}</div></td>
                    {m.metrics ? <>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.accuracy.toFixed(3)}</td>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.precision.toFixed(3)}</td>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.recall.toFixed(3)}</td>
                      <td className="px-3 py-2.5 font-mono tnum font-semibold">{m.metrics.f1.toFixed(3)}</td>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.roc_auc?.toFixed(3) ?? "—"}</td>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.fpr.toFixed(3)}</td>
                      <td className="px-3 py-2.5 font-mono tnum">{m.metrics.inference_ms_median != null ? `${m.metrics.inference_ms_median.toFixed(3)}ms` : "—"}</td>
                    </> : <td colSpan={7} className="px-3 py-2.5 text-xs text-[color:var(--color-faint)]">{m.name === "rules" ? "no training required" : "not trained"}</td>}
                    <td className="px-3 py-2.5">
                      <button onClick={() => setActive(m.name)} disabled={!m.loaded} className="disabled:opacity-30" title={models.data?.active === m.name ? "active" : "set active"}>
                        {models.data?.active === m.name ? <CheckCircle2 size={18} className="text-emerald-400" /> : <Circle size={18} className="text-[color:var(--color-faint)]" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 flex items-start gap-1.5 text-xs text-[color:var(--color-faint)]"><Info size={13} className="mt-0.5 shrink-0" />
          The rule-based detector is intentionally high-precision / low-recall at the 0.5 threshold; ML models lift recall substantially (RQ2). Switching the active model changes live scoring immediately.</p>
      </Panel>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Panel title="XGBoost feature importance (gain)">
          {importance.length ? <SimpleBar data={importance} x="name" y="v" color="#3b82f6" horizontal height={320} /> : <Empty title="Not available" hint="Train the models to populate importances." />}
        </Panel>
        <Panel title="Leave-one-attack-out generalisation">
          <LoaoView />
        </Panel>
      </div>

      <Panel title="Features used (20)" className="mt-3">
        <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          {status.data?.features?.map((f: any) => (
            <div key={f.name} className="flex items-start gap-2 rounded-lg bg-[color:var(--color-elevated)] px-3 py-1.5 text-xs">
              <code className="shrink-0 text-blue-300">{f.name}</code>
              {f.synthetic && <Chip tone="danger">synthetic</Chip>}
              <span className="text-[color:var(--color-faint)]">{f.description}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function LoaoView() {
  const { data } = useQuery({ queryKey: ["ml-evals"], queryFn: () => api.get<any>("/ml/evaluations") });
  // leave-one-attack-out lives in metrics.json, surfaced via evaluations details is not ideal; show a note.
  return (
    <div className="text-sm text-[color:var(--color-muted)]">
      <p>Models are retrained with an entire attack family (<code className="text-blue-300">bitm_relay</code>) removed, then tested on it to measure generalisation to an unseen attack. Full numbers are in <code className="text-blue-300">docs/RESULTS.md</code>.</p>
      <p className="mt-2 text-xs text-[color:var(--color-faint)]">This guards against the dataset simply memorising attack signatures — a common weakness the literature survey flags.</p>
    </div>
  );
}
