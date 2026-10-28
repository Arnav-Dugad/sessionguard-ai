import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Settings as SettingsIcon, Monitor, Moon, Sun, RefreshCw, Trash2, Cpu, Database } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/Layout";
import { Panel, Chip, StatTile } from "@/components/ui";
import { useAuth } from "@/lib/auth";

function applyTheme(t: string) {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", t);
  try { localStorage.setItem("sg-theme", t); } catch { /* ignore */ }
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem("sg-theme") || "dark"; } catch { return "dark"; } });
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.get<any>("/meta") });
  const status = useQuery({ queryKey: ["ml-status"], queryFn: () => api.get<any>("/ml/status") });
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.get<any>("/health") });

  const resetLab = async () => { await api.post("/simulation/reset"); toast.success("Lab sessions revoked"); qc.invalidateQueries(); };
  const reloadModels = async () => { await api.post("/ml/reload"); toast.success("Models reloaded from disk"); qc.invalidateQueries(); };

  return (
    <div>
      <PageHeader title="System Settings" icon={SettingsIcon} subtitle="Appearance, model status and demonstration controls." />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Panel title="Appearance">
          <p className="mb-3 text-xs text-[color:var(--color-faint)]">SessionGuard is a dark-first SOC product; a light theme is available for projectors.</p>
          <div className="flex gap-2">
            {[{ k: "dark", i: Moon, l: "Dark" }, { k: "light", i: Sun, l: "Light" }, { k: "system", i: Monitor, l: "System" }].map((t) => (
              <button key={t.k} onClick={() => { setTheme(t.k); applyTheme(t.k); }}
                className={`flex flex-1 flex-col items-center gap-1.5 rounded-lg border px-3 py-3 text-xs transition-colors ${theme === t.k ? "border-blue-500/50 bg-blue-500/10 text-blue-200" : "border-[color:var(--color-border-strong)] bg-[color:var(--color-elevated)] text-[color:var(--color-muted)]"}`}>
                <t.i size={18} /> {t.l}
              </button>
            ))}
          </div>
        </Panel>

        <Panel title="Detection model" action={<Chip tone={status.data?.loaded ? "success" : "warning"}>{status.data?.loaded ? "loaded" : "rule-only"}</Chip>}>
          <div className="space-y-2 text-sm">
            <Row k="Active model" v={status.data?.active_label} />
            <Row k="Version" v={status.data?.version} mono />
            <Row k="Dataset" v={status.data?.dataset_version} mono />
            <Row k="Trained at" v={status.data?.trained_at ?? "not trained"} mono />
            <Row k="Seed" v={status.data?.seed} mono />
          </div>
          <button className="btn mt-3 w-full" onClick={reloadModels}><RefreshCw size={14} /> Reload models from disk</button>
        </Panel>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile label="Backend" value={<span className="text-base">{health.data?.status ?? "—"}</span>} sub={meta.data?.app} icon={<Database size={16} />} tone="success" />
        <StatTile label="Environment" value={<span className="text-base">{meta.data?.environment ?? "—"}</span>} tone="accent" />
        <StatTile label="Scenarios" value={meta.data?.scenarios ?? "—"} icon={<Cpu size={16} />} tone="cyan" />
        <StatTile label="Version" value={<span className="text-base">{meta.data?.version ?? "—"}</span>} tone="warning" />
      </div>

      <Panel title="Demonstration controls" className="mt-3">
        <div className="flex flex-wrap gap-2">
          <button className="btn btn-danger" onClick={resetLab}><Trash2 size={14} /> Reset lab (revoke all lab sessions)</button>
        </div>
        <p className="mt-3 text-xs text-[color:var(--color-faint)]">Demo accounts — <span className="font-mono">ada</span> / <span className="font-mono">Demo-User!2027</span> · <span className="font-mono">grace</span> / <span className="font-mono">Demo-User!2027</span> · <span className="font-mono">admin</span> / <span className="font-mono">Admin-SOC!2027</span>. All identities and data are fictional.</p>
        <p className="mt-1 text-xs text-[color:var(--color-faint)]">Signed in as <b>{user?.username}</b> ({user?.role}).</p>
      </Panel>
    </div>
  );
}

function Row({ k, v, mono }: { k: string; v: any; mono?: boolean }) {
  return <div className="flex items-center justify-between border-b border-[color:var(--color-border)]/60 py-1.5 last:border-0"><span className="text-[color:var(--color-muted)]">{k}</span><span className={mono ? "font-mono text-xs" : ""}>{String(v ?? "—")}</span></div>;
}
