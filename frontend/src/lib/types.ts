export type Band = "low" | "elevated" | "high" | "critical" | "n/a";

export interface User {
  id: number; username: string; email: string; display_name: string; role: string; is_demo: boolean; created_at: string;
}

export interface SessionInfo {
  id: string; fingerprint: string; username: string; user_role: string;
  created_at: string; last_activity: string; expires_at: string; revoked_at: string | null; revoked_reason: string | null;
  device: Record<string, any>; network: Record<string, any>; baseline_device: Record<string, any>; baseline_network: Record<string, any>;
  risk_score: number; peak_risk: number; band: Band; status: string; protection_mode: string; is_lab: boolean;
  request_count: number; step_up_until: string | null; is_current: boolean;
}

export interface SecurityEvent {
  id: string; timestamp: string; event_type: string; category: string; severity: string;
  explanation: string; detection_method: string; action_taken: string;
  risk_before: number; risk_after: number; risk_score: number; synthetic: boolean; is_lab: boolean;
  session_ref: string | null; username: string | null; simulation_run_id: number | null; metadata: Record<string, any>;
}

export interface Contribution { label: string; points: number; strength: number; weight: number | null; detail: string; synthetic: boolean; }

export interface Overview {
  generated_at: string; active_sessions: number; total_users: number; under_investigation: number;
  threats_detected: number; threats_24h: number; auto_revoked: number; step_up_challenges: number;
  avg_risk: number; auth_failures_24h: number; recent_auth_failures: SecurityEvent[];
  detection_latency_ms: { mean: number | null; p95: number | null; samples: number };
  inference_ms: { median: number | null; samples: number };
  containment_latency_s: number | null; events_per_minute: number;
  band_distribution: Record<string, number>; model: ModelStatus;
  policy: { thresholds: Record<string, number>; enforcement: string; critical_action: string };
  websocket_clients: number;
}

export interface ModelStatus {
  active_model: string; active_label: string; loaded: boolean; version: string; available: string[];
  features: string[]; trained_at: string | null; dataset_version: string | null; seed: number | null;
}

export interface Scenario {
  key: string; name: string; tagline: string; icon: string; category: string; threat_level: string;
  rq: string[]; summary: string; teaches: string; clients: string[]; step_count: number;
  steps: { index: number; title: string; action: string; client: string; path: string; explanation: string; expect: string; malicious: boolean; synthetic: boolean; repeat: number }[];
}

export interface Exchange {
  client: string; client_label: string; role: string; malicious: boolean; method: string; path: string;
  status: number; ok: boolean; response: any; risk: number | null; band: Band | null; decision: string | null;
  request_log_id: number | null; virtual_ts: number; latency_ms: number; request_headers: Record<string, string>; note: string;
}

export interface StepResult {
  index: number; title: string; action: string; client: string; explanation: string; expect: string; note: string;
  exchanges: Exchange[]; events: SecurityEvent[]; wall_ms: number; virtual_clock: number; malicious: boolean;
  has_next: boolean; run_id: number; final?: RunSummary;
}

export interface RunSummary {
  run_id: number; scenario: string; mode: string; status: string;
  summary: {
    outcome: string; detected: boolean; revoked: boolean; challenged: boolean;
    attacker_requests: number; attacker_accepted: number; attacker_blocked: number; peak_risk: number;
    threat_events: number; total_events: number; detection_latency_s: number | null;
    containment_latency_s: number | null; detection_wall_ms: number | null;
  };
}

export interface Incident {
  id: string; session: SessionInfo; kind: string; title: string; severity: string; status: string;
  alert_count: number; first_seen: string; last_seen: string; peak_risk: number; event_types: string[];
  synthetic: boolean; latest: SecurityEvent;
}

export interface Policy {
  weights: Record<string, number>;
  thresholds: { elevated: number; high: number; critical: number };
  decay_per_request: number; half_life_s: number; ml_floor: number;
  critical_action: string; step_up_on_context_change: boolean; context_change_threshold: number;
  enforcement: string; ml_enabled: boolean;
}
