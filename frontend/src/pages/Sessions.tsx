import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ListTree, Ban, Search, Shield, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { SessionInfo } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, BandBadge, Chip, Toggle, Empty } from "@/components/ui";
import { fmtTime, timeAgo, cn } from "@/lib/utils";

const STATUS_TONE: Record<string, string> = {
  active: "success", step_up: "warning", revoked: "danger", expired: "muted", logged_out: "muted", rotated: "muted",
};

export default function Sessions() {
  const qc = useQueryClient();
  const [onlyActive, setOnlyActive] = useState(true);
  const [includeLab, setIncludeLab] = useState(true);
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["admin-sessions", onlyActive, includeLab],
    queryFn: () => api.get<{ sessions: SessionInfo[] }>(`/security/sessions?include_lab=${includeLab}${onlyActive ? "&status=active" : ""}`),
    refetchInterval: 5000,
  });
  const detail = useQuery({
    queryKey: ["session-detail", selected],
    queryFn: () => api.get<any>(`/sessions/${selected}`),
    enabled: !!selected,
  });

  const rows = (data?.sessions ?? []).filter((s) =>
    !q || s.username?.toLowerCase().includes(q.toLowerCase()) || s.id.includes(q) || (s.network?.region ?? "").toLowerCase().includes(q.toLowerCase()));

  const revoke = async (id: string) => {
    try { await api.del(`/sessions/${id}`); toast.success(`Revoked ${id}`); qc.invalidateQueries({ queryKey: ["admin-sessions"] }); if (selected === id) detail.refetch(); }
    catch (e: any) { toast.error(e.message); }
  };

  return (
    <div>
      <PageHeader title="Active Sessions" icon={ListTree}
        subtitle="Every server-side session with its live trust score. Revocation is enforced on the backend."
        actions={
          <div className="flex items-center gap-3 text-xs">
            <label className="flex items-center gap-1.5">Active only <Toggle checked={onlyActive} onChange={setOnlyActive} /></label>
            <label className="flex items-center gap-1.5">Include lab <Toggle checked={includeLab} onChange={setIncludeLab} /></label>
            <button className="btn btn-ghost" onClick={() => qc.invalidateQueries({ queryKey: ["admin-sessions"] })}><RefreshCw size={14} /></button>
          </div>
        }
      />
      <div className="relative mb-3 max-w-sm">
        <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-faint)]" />
        <input className="input pl-9" placeholder="Search user, session id, region…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_380px]">
        <Panel className="overflow-hidden !p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[color:var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[color:var(--color-faint)]">
                  {["Session", "User", "Device", "Network", "Risk", "Status", "Last activity", ""].map((h) => <th key={h} className="px-3 py-2.5 font-medium">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {isLoading ? [...Array(6)].map((_, i) => <tr key={i}><td colSpan={8} className="px-3 py-2"><div className="skeleton h-6" /></td></tr>)
                  : rows.length === 0 ? <tr><td colSpan={8} className="p-6"><Empty title="No sessions" hint="Sign in from the portal or run a lab scenario." /></td></tr>
                  : rows.map((s) => (
                    <tr key={s.id} onClick={() => setSelected(s.id)}
                      className={cn("cursor-pointer border-b border-[color:var(--color-border)]/60 transition-colors hover:bg-white/[0.03]", selected === s.id && "bg-blue-500/10")}>
                      <td className="px-3 py-2.5"><span className="font-mono text-xs">{s.id}</span>{s.is_lab && <span className="ml-1.5 chip bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/20">lab</span>}</td>
                      <td className="px-3 py-2.5">{s.username}{s.user_role === "admin" && <Shield size={11} className="ml-1 inline text-blue-300" />}</td>
                      <td className="px-3 py-2.5 text-xs text-[color:var(--color-muted)]">{s.device?.label ?? "—"}</td>
                      <td className="px-3 py-2.5 text-xs text-[color:var(--color-muted)]">{s.network?.region ?? "—"}</td>
                      <td className="px-3 py-2.5"><div className="flex items-center gap-2"><span className="font-mono tnum w-8">{s.risk_score.toFixed(0)}</span><BandBadge band={s.band} /></div></td>
                      <td className="px-3 py-2.5"><Chip tone={STATUS_TONE[s.status] as any}>{s.status.replace(/_/g, " ")}</Chip></td>
                      <td className="px-3 py-2.5 text-xs text-[color:var(--color-faint)]">{timeAgo(s.last_activity)}</td>
                      <td className="px-3 py-2.5">
                        {(s.status === "active" || s.status === "step_up") && !s.is_current &&
                          <button className="btn btn-ghost !px-2 !py-1 text-xs text-red-300" onClick={(e) => { e.stopPropagation(); revoke(s.id); }}><Ban size={13} /></button>}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <SessionDetail detail={detail.data} loading={detail.isFetching} onRevoke={revoke} empty={!selected} />
      </div>
    </div>
  );
}

function SessionDetail({ detail, loading, onRevoke, empty }: { detail: any; loading: boolean; onRevoke: (id: string) => void; empty: boolean }) {
  if (empty) return <Panel><Empty icon={<ListTree size={26} />} title="Select a session" hint="Click any row to inspect its telemetry, risk history and events." /></Panel>;
  if (loading || !detail) return <Panel><div className="space-y-2">{[...Array(6)].map((_, i) => <div key={i} className="skeleton h-5" />)}</div></Panel>;
  const s: SessionInfo = detail.session;
  return (
    <Panel title="Session detail" action={(s.status === "active" || s.status === "step_up") && !s.is_current && <button className="btn btn-danger !py-1 text-xs" onClick={() => onRevoke(s.id)}><Ban size={13} /> Revoke</button>}>
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="font-mono text-sm">{s.id}</span><BandBadge band={s.band} />
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[["User", s.username], ["Status", s.status.replace(/_/g, " ")], ["Risk", s.risk_score.toFixed(1)], ["Peak", s.peak_risk.toFixed(1)],
            ["Device", s.device?.label], ["Network", s.network?.network], ["Region", s.network?.region], ["Requests", s.request_count],
            ["Fingerprint", s.fingerprint], ["Mode", s.protection_mode]].map(([k, v]) => (
            <div key={k as string} className="rounded-lg bg-[color:var(--color-elevated)] px-2.5 py-1.5">
              <div className="text-[10px] uppercase tracking-wider text-[color:var(--color-faint)]">{k}</div>
              <div className="mt-0.5 truncate font-mono">{String(v ?? "—")}</div>
            </div>
          ))}
        </div>
        {detail.requests?.length > 0 && (
          <div>
            <h4 className="card-title mb-1.5">Recent requests</h4>
            <div className="max-h-56 space-y-1 overflow-y-auto pr-1">
              {detail.requests.slice(0, 20).map((r: any) => (
                <div key={r.id} className="flex items-center gap-2 rounded bg-[color:var(--color-elevated)] px-2 py-1 text-[11px]">
                  <span className="font-mono text-[color:var(--color-faint)]">{fmtTime(new Date(r.ts * 1000).toISOString())}</span>
                  <span className="rounded bg-black/30 px-1 font-mono">{r.method}</span>
                  <span className="truncate text-[color:var(--color-muted)]">{r.path}</span>
                  <span className={cn("ml-auto font-mono", r.status >= 400 ? "text-red-300" : "text-emerald-300")}>{r.status}</span>
                  <span className="font-mono tnum">{r.risk?.toFixed(0)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}
