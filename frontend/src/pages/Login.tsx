import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, Lock, User, ArrowRight, Terminal } from "lucide-react";
import { toast } from "sonner";
import { useAuth, isAuthError } from "@/lib/auth";
import { Brand } from "@/components/Layout";
import { Spinner } from "@/components/ui";

const DEMO = [
  { label: "SOC Admin", username: "admin", password: "Admin-SOC!2027", desc: "Full security console" },
  { label: "Standard user", username: "ada", password: "Demo-User!2027", desc: "User portal (Ada)" },
];

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (u: string, p: string) => {
    setBusy(true);
    try {
      await login(u, p);
      toast.success(`Signed in as ${u}`);
    } catch (e) {
      toast.error(isAuthError(e) ? e.message : "Sign-in failed");
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Left: brand / story */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-[color:var(--color-border)] p-10 lg:flex">
        <div className="grid-bg pointer-events-none absolute inset-0 opacity-40" />
        <div className="pointer-events-none absolute -right-24 top-10 h-72 w-72 rounded-full bg-blue-500/20 blur-3xl" />
        <div className="pointer-events-none absolute bottom-0 left-10 h-64 w-64 rounded-full bg-cyan-500/15 blur-3xl" />
        <div className="relative"><Brand /></div>
        <div className="relative max-w-md">
          <motion.h1 initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}
            className="text-3xl font-semibold leading-tight tracking-tight">
            Detect hijacked sessions<br />even with a <span className="text-blue-400">valid token</span>.
          </motion.h1>
          <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.1 }}
            className="mt-4 text-sm leading-relaxed text-[color:var(--color-muted)]">
            SessionGuard AI fuses per-request telemetry, machine-learning anomaly detection and continuous risk
            scoring to drive automated Zero-Trust containment — revoking compromised sessions server-side, not just
            in the UI.
          </motion.p>
          <div className="mt-6 flex flex-wrap gap-2">
            {["Telemetry", "ML detection", "Risk scoring", "Zero-Trust containment"].map((s, i) => (
              <motion.span key={s} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 + i * 0.08 }}
                className="chip bg-white/5 ring-1 ring-[color:var(--color-border-strong)]">{s}</motion.span>
            ))}
          </div>
        </div>
        <div className="relative text-xs text-[color:var(--color-faint)]">Academic demonstration · fully offline · synthetic data only</div>
      </div>

      {/* Right: form */}
      <div className="flex items-center justify-center p-6">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }} className="panel w-full max-w-sm p-6">
          <div className="mb-6 flex items-center gap-2 lg:hidden"><Brand /></div>
          <div className="mb-5">
            <div className="grid h-11 w-11 place-items-center rounded-xl bg-blue-500/15 ring-1 ring-blue-500/30"><ShieldCheck className="text-blue-300" size={22} /></div>
            <h2 className="mt-3 text-lg font-semibold">Sign in to the console</h2>
            <p className="text-sm text-[color:var(--color-muted)]">Use a seeded demo account below.</p>
          </div>

          <form onSubmit={(e) => { e.preventDefault(); submit(username, password); }} className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-[color:var(--color-muted)]">Username</span>
              <div className="relative">
                <User size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-faint)]" />
                <input className="input pl-9" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="ada" autoComplete="username" />
              </div>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-[color:var(--color-muted)]">Password</span>
              <div className="relative">
                <Lock size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-faint)]" />
                <input type="password" className="input pl-9" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" />
              </div>
            </label>
            <button className="btn btn-primary w-full" disabled={busy || !username || !password}>
              {busy ? <Spinner /> : <>Sign in <ArrowRight size={16} /></>}
            </button>
          </form>

          <div className="my-4 flex items-center gap-3 text-[11px] uppercase tracking-wider text-[color:var(--color-faint)]">
            <div className="h-px flex-1 bg-[color:var(--color-border)]" /> quick demo login <div className="h-px flex-1 bg-[color:var(--color-border)]" />
          </div>
          <div className="space-y-2">
            {DEMO.map((d) => (
              <button key={d.username} onClick={() => submit(d.username, d.password)} disabled={busy}
                className="group flex w-full items-center justify-between rounded-lg border border-[color:var(--color-border-strong)] bg-[color:var(--color-elevated)] px-3 py-2 text-left transition-colors hover:bg-[color:var(--color-overlay)]">
                <span>
                  <span className="block text-sm font-medium">{d.label}</span>
                  <span className="block text-[11px] text-[color:var(--color-faint)]">{d.desc}</span>
                </span>
                <span className="flex items-center gap-1.5 font-mono text-[11px] text-[color:var(--color-muted)]"><Terminal size={13} /> {d.username}</span>
              </button>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
