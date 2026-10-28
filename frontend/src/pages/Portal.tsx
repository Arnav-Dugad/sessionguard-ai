import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { UserRound, FileText, Wallet, Download, Send, ShieldCheck, Ban, LogOut, Lock, Monitor, Globe } from "lucide-react";
import { toast } from "sonner";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { SessionInfo } from "@/lib/types";
import { PageHeader } from "@/components/Layout";
import { Panel, Chip, BandBadge, Spinner, Empty } from "@/components/ui";
import { EventFeed } from "@/components/EventFeed";
import { fmtDateTime, timeAgo } from "@/lib/utils";

export default function Portal() {
  const qc = useQueryClient();
  const { user, session, reauth } = useAuth();
  const [stepUp, setStepUp] = useState<null | { retry: () => void }>(null);

  const dash = useQuery({ queryKey: ["portal-dash"], queryFn: () => api.get<any>("/portal/dashboard") });
  const docs = useQuery({ queryKey: ["portal-docs"], queryFn: () => api.get<any>("/portal/documents") });
  const sessions = useQuery({ queryKey: ["my-sessions"], queryFn: () => api.get<{ sessions: SessionInfo[] }>("/sessions"), refetchInterval: 6000 });
  const activity = useQuery({ queryKey: ["my-activity"], queryFn: () => api.get<any>("/portal/activity"), refetchInterval: 6000 });

  const sensitive = async (fn: () => Promise<any>, label: string) => {
    try { await fn(); toast.success(`${label} complete`); qc.invalidateQueries(); }
    catch (e) {
      if (e instanceof ApiError && e.code === "step_up_required") {
        setStepUp({ retry: () => sensitive(fn, label) });
        toast.warning("Additional verification required");
      } else if (e instanceof ApiError && (e.code === "session_revoked_risk" || e.code === "session_revoked")) {
        toast.error("Session revoked by SessionGuard"); window.location.reload();
      } else toast.error(e instanceof ApiError ? e.message : "Action failed");
    }
  };

  const revoke = async (id: string) => { try { await api.del(`/sessions/${id}`); toast.success("Session revoked"); qc.invalidateQueries({ queryKey: ["my-sessions"] }); } catch (e: any) { toast.error(e.message); } };
  const revokeOthers = async () => { try { const r = await api.post<any>("/sessions/revoke-all?scope=mine"); toast.success(`Revoked ${r.revoked} other session(s)`); qc.invalidateQueries({ queryKey: ["my-sessions"] }); } catch (e: any) { toast.error(e.message); } };

  return (
    <div>
      <PageHeader title="Helios Vault" icon={UserRound}
        subtitle={<>Fictional demo application · signed in as <b>{user?.display_name || user?.username}</b></>}
        actions={session && <span className="flex items-center gap-2 text-xs"><BandBadge band={session.band} /> <span className="font-mono text-[color:var(--color-faint)]">{session.id}</span></span>} />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div className="space-y-3 lg:col-span-2">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Panel>
              <div className="flex items-center justify-between"><span className="card-title">Balance</span><Wallet size={16} className="text-emerald-300" /></div>
              <div className="mt-2 text-3xl font-semibold tnum">{dash.data ? `${dash.data.balance.toLocaleString()} cr` : "—"}</div>
              <div className="mt-3 flex gap-2">
                <button className="btn btn-primary flex-1" onClick={() => sensitive(() => api.post("/portal/transfer", { recipient: "orbit-logistics", amount: 250, memo: "demo" }), "Transfer")}><Send size={14} /> Transfer 250</button>
                <button className="btn flex-1" onClick={() => sensitive(() => api.post("/portal/export"), "Export")}><Download size={14} /> Export</button>
              </div>
              <p className="mt-2 text-[11px] text-[color:var(--color-faint)]">Sensitive actions may require step-up verification when risk is elevated.</p>
            </Panel>
            <Panel>
              <div className="flex items-center justify-between"><span className="card-title">Projects</span></div>
              <div className="mt-2 space-y-2">
                {dash.data?.projects?.map((p: any) => (
                  <div key={p.name}><div className="flex justify-between text-xs"><span>{p.name}</span><span className="font-mono text-[color:var(--color-faint)]">{p.progress}%</span></div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-[color:var(--color-elevated)]"><div className="h-full bg-blue-500" style={{ width: `${p.progress}%` }} /></div></div>
                )) ?? [...Array(3)].map((_, i) => <div key={i} className="skeleton h-5" />)}
              </div>
            </Panel>
          </div>

          <Panel title="Documents" action={<Chip tone="muted">{docs.data?.documents?.length ?? 0} files</Chip>}>
            <div className="space-y-1.5">
              {docs.data?.documents?.map((d: any) => (
                <button key={d.id} onClick={() => sensitive(() => api.get(`/portal/documents/${d.id}`), "Open")}
                  className="flex w-full items-center gap-3 rounded-lg bg-[color:var(--color-elevated)] px-3 py-2 text-left text-sm transition-colors hover:bg-[color:var(--color-overlay)]">
                  <FileText size={15} className="text-blue-300" /><span className="flex-1 truncate">{d.title}</span>
                  <Chip tone={d.classification === "restricted" || d.classification === "confidential" ? "danger" : "muted"}>{d.classification}</Chip>
                </button>
              )) ?? [...Array(4)].map((_, i) => <div key={i} className="skeleton h-9" />)}
            </div>
          </Panel>

          <Panel title="Your account activity">
            {activity.data?.events?.length ? <div className="max-h-72 overflow-y-auto pr-1"><EventFeed events={activity.data.events} /></div> : <Empty title="No activity yet" />}
          </Panel>
        </div>

        <div className="space-y-3">
          <Panel title="Active sessions" action={<button className="btn btn-ghost !py-1 text-xs" onClick={revokeOthers}>Revoke others</button>}>
            <div className="space-y-2">
              {sessions.data?.sessions?.filter((s) => s.status === "active" || s.status === "step_up").map((s) => (
                <div key={s.id} className={`rounded-lg border p-2.5 ${s.is_current ? "border-blue-500/40 bg-blue-500/[0.06]" : "border-[color:var(--color-border)] bg-[color:var(--color-elevated)]"}`}>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs font-medium">{s.device?.device_type === "mobile" ? <Monitor size={13} /> : <Monitor size={13} />}{s.is_current && <Chip tone="accent">this device</Chip>}</span>
                    <BandBadge band={s.band} />
                  </div>
                  <div className="mt-1.5 space-y-0.5 text-[11px] text-[color:var(--color-muted)]">
                    <div className="flex items-center gap-1.5"><Monitor size={11} /> {s.device?.label}</div>
                    <div className="flex items-center gap-1.5"><Globe size={11} /> {s.network?.network} · {s.network?.region}</div>
                    <div className="text-[color:var(--color-faint)]">active {timeAgo(s.last_activity)} · {s.request_count} requests</div>
                  </div>
                  {!s.is_current && <button className="btn btn-ghost mt-2 w-full !py-1 text-xs text-red-300" onClick={() => revoke(s.id)}><Ban size={12} /> Revoke</button>}
                </div>
              )) ?? <div className="skeleton h-20" />}
            </div>
          </Panel>

          <Panel title="Profile">
            <div className="space-y-1.5 text-sm">
              <Row k="Username" v={user?.username} /><Row k="Email" v={user?.email} /><Row k="Role" v={user?.role} />
              {session && <Row k="Member since" v={fmtDateTime(session.created_at)} />}
            </div>
          </Panel>
        </div>
      </div>

      {stepUp && <StepUpModal onClose={() => setStepUp(null)} onVerify={async (pw) => { await reauth(pw); const r = stepUp.retry; setStepUp(null); toast.success("Verified — trust re-established"); setTimeout(r, 300); }} />}
    </div>
  );
}

function Row({ k, v }: { k: string; v: any }) {
  return <div className="flex items-center justify-between"><span className="text-[color:var(--color-muted)]">{k}</span><span className="truncate font-mono text-xs">{String(v ?? "—")}</span></div>;
}

function StepUpModal({ onClose, onVerify }: { onClose: () => void; onVerify: (pw: string) => Promise<void> }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => { setBusy(true); try { await onVerify(pw); } catch (e: any) { toast.error(e.message ?? "Verification failed"); setBusy(false); } };
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="panel w-full max-w-sm p-6" onClick={(e) => e.stopPropagation()}>
        <div className="grid h-11 w-11 place-items-center rounded-xl bg-orange-500/15 ring-1 ring-orange-500/30"><Lock className="text-orange-300" size={20} /></div>
        <h2 className="mt-3 text-lg font-semibold">Confirm it's you</h2>
        <p className="mt-1 text-sm text-[color:var(--color-muted)]">This session's risk is elevated, so SessionGuard requires a fresh password challenge before this sensitive action. (This is a password re-check, not MFA.)</p>
        <form onSubmit={(e) => { e.preventDefault(); submit(); }} className="mt-4 space-y-3">
          <input type="password" className="input" placeholder="Your password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
          <div className="flex gap-2">
            <button type="button" className="btn flex-1" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary flex-1" disabled={busy || !pw}>{busy ? <Spinner /> : <><ShieldCheck size={15} /> Verify</>}</button>
          </div>
        </form>
      </div>
    </div>
  );
}
