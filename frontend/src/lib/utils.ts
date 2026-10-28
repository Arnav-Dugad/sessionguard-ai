import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Band } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const BAND_META: Record<string, { label: string; color: string; text: string; bg: string; ring: string }> = {
  low: { label: "Low", color: "var(--color-success)", text: "text-emerald-300", bg: "bg-emerald-500/12", ring: "ring-emerald-500/30" },
  elevated: { label: "Elevated", color: "var(--color-warning)", text: "text-amber-300", bg: "bg-amber-500/12", ring: "ring-amber-500/30" },
  high: { label: "High", color: "var(--color-high)", text: "text-orange-300", bg: "bg-orange-500/12", ring: "ring-orange-500/30" },
  critical: { label: "Critical", color: "var(--color-critical)", text: "text-red-300", bg: "bg-red-500/12", ring: "ring-red-500/30" },
  "n/a": { label: "N/A", color: "var(--color-faint)", text: "text-slate-400", bg: "bg-slate-500/10", ring: "ring-slate-500/20" },
};

export function bandFor(score: number): Band {
  return score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "elevated" : "low";
}

export const SEVERITY_META: Record<string, { text: string; dot: string; label: string }> = {
  info: { text: "text-slate-300", dot: "bg-slate-400", label: "Info" },
  low: { text: "text-sky-300", dot: "bg-sky-400", label: "Low" },
  medium: { text: "text-amber-300", dot: "bg-amber-400", label: "Medium" },
  high: { text: "text-orange-300", dot: "bg-orange-400", label: "High" },
  critical: { text: "text-red-300", dot: "bg-red-400", label: "Critical" },
};

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function eventLabel(t: string): string {
  return t.replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}
