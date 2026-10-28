import { AnimatePresence, motion } from "framer-motion";
import { eventLabel, fmtTime, SEVERITY_META } from "@/lib/utils";
import { SeverityDot } from "./ui";
import type { SecurityEvent } from "@/lib/types";

const ACTION_TONE: Record<string, string> = {
  revoke_session: "text-red-300", step_up_required: "text-orange-300", deny_401: "text-red-300",
  deny_403: "text-orange-300", allow: "text-emerald-300", re_baseline: "text-emerald-300",
};

export function EventRow({ ev, onClick }: { ev: SecurityEvent; onClick?: () => void }) {
  const sev = SEVERITY_META[ev.severity] ?? SEVERITY_META.info;
  return (
    <motion.button
      layout initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
      onClick={onClick}
      className="group flex w-full items-start gap-3 rounded-lg border border-transparent px-3 py-2 text-left transition-colors hover:border-[color:var(--color-border)] hover:bg-white/[0.03]"
    >
      <div className="mt-1.5"><SeverityDot severity={ev.severity} /></div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className={`text-sm font-medium ${sev.text}`}>{eventLabel(ev.event_type)}</span>
          {ev.synthetic && <span className="chip bg-fuchsia-500/12 text-fuchsia-300 ring-1 ring-fuchsia-500/25">synthetic</span>}
          {ev.is_lab && <span className="chip bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/20">lab</span>}
        </div>
        <p className="mt-0.5 line-clamp-2 text-xs text-[color:var(--color-muted)]">{ev.explanation}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-[color:var(--color-faint)]">
          <span className="font-mono">{fmtTime(ev.timestamp)}</span>
          {ev.session_ref && <span className="font-mono">{ev.session_ref}</span>}
          {ev.username && <span>{ev.username}</span>}
          {ev.detection_method !== "none" && <span className="font-mono">{ev.detection_method}</span>}
          {ev.action_taken !== "none" && <span className={`font-mono ${ACTION_TONE[ev.action_taken] ?? ""}`}>{ev.action_taken}</span>}
          {ev.risk_after > 0 && <span className="font-mono">risk {ev.risk_before.toFixed(0)}→{ev.risk_after.toFixed(0)}</span>}
        </div>
      </div>
    </motion.button>
  );
}

export function EventFeed({ events, onSelect, max = 60 }: { events: SecurityEvent[]; onSelect?: (e: SecurityEvent) => void; max?: number }) {
  return (
    <div className="space-y-0.5">
      <AnimatePresence initial={false}>
        {events.slice(0, max).map((ev) => <EventRow key={ev.id} ev={ev} onClick={onSelect ? () => onSelect(ev) : undefined} />)}
      </AnimatePresence>
    </div>
  );
}
