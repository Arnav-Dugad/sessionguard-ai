# SessionGuard AI — Master Build Specification (v2)

> This is a rewritten, tightened version of the original "Master Development Prompt".
> The original was strong on *what* but left many *how* decisions open, contained a few
> internal contradictions, and had no machine-checkable definition of done. v2 fixes that.
> Every section below is written so a coding agent (or a human team) can implement it
> without guessing, and so a reviewer can verify it without trusting claims.

---

## 0. What changed from v1 (and why)

| Problem in v1 | Fix in v2 |
|---|---|
| "Role-play an elite team" adds tokens, not precision. | Replaced with explicit engineering constraints and acceptance tests. |
| Telemetry was described, but local demos all come from `127.0.0.1` — a second "client context" is impossible without spoofing. | Defined a **controlled in-process harness**: real HTTP requests through the full ASGI stack, with the simulated client address set at the transport layer (not via spoofable headers). |
| Scenario timing (bursts vs. normal browsing) collapses when a 5-minute demo runs in 20 seconds. | Added a **signed virtual clock** that only the harness can use; every simulated timestamp is labelled. |
| "Synthetic BITM / OIDC signals" had no defined injection path. | Synthetic signals are accepted **only** from harness requests carrying a per-process secret, and are tagged `synthetic=true` in every event. |
| Dataset leakage was warned about, but no protocol given. | Group split by session, presence-of-feature randomised independently of label, plus a **leave-one-attack-out** generalisation test. |
| Risk formula undefined ("configurable combination"). | Defined a **noisy-OR evidence fusion** with correlation groups, proportional attribution, and decay. |
| Additive point scores can exceed 100 and double-count. | Noisy-OR is bounded in [0,100] and treats correlated features as one group (max, not sum). |
| "World-class UI" was adjectives only. | Added a **design-system and motion spec** with tokens, durations, easing and reduced-motion rules. |
| No definition of done. | Section 13 lists acceptance tests that must pass in CI (`pytest`) and manual demo checks. |
| PyTorch for one AutoEncoder adds a 200 MB+ dependency. | AutoEncoder implemented with scikit-learn's MLP (tied encode/decode, latent extracted from weights) — offline-friendly and CPU-fast. |

---

## 1. Mission

Build **SessionGuard AI** — *Detect. Analyze. Contain. Protect.* — a locally runnable (Windows 11,
offline) system that answers one question with measured evidence:

> **Can reuse of a technically valid session token be detected and contained automatically?**

It must implement, in one working pipeline:

1. **Telemetry collection** (server-observed, per request)
2. **ML anomaly detection** (rules baseline, Logistic Regression, XGBoost, AutoEncoder+XGBoost)
3. **Continuous, explainable risk scoring** (0–100)
4. **Automated Zero-Trust containment** (allow → monitor → step-up → revoke)

…and demonstrate the difference between **conventional** validation (exists / not expired / not revoked)
and **risk-aware** validation on the *same* request streams.

Scope boundary (non-negotiable): only the application's own synthetic accounts and sessions.
No browser cookie extraction, phishing proxies, credential harvesting, real IP spoofing or third-party targets.

---

## 2. Stack (fixed)

- **Frontend**: React 19 + TypeScript + Vite, Tailwind CSS v4, shadcn-style components (Radix primitives,
  copied in — no CLI dependency), Framer Motion, Recharts, Lucide, React Router, TanStack Query, `cmdk`, `sonner`.
  Fonts are bundled via Fontsource (Inter, JetBrains Mono) so the UI works offline.
- **Backend**: Python 3.12+ (3.13 tested), FastAPI, Uvicorn, SQLAlchemy 2, Alembic, Pydantic v2, SQLite (WAL).
- **ML**: scikit-learn, XGBoost, NumPy, Pandas, Joblib. No GPU required.
- **Security**: `secrets.token_urlsafe(32)` session tokens, HMAC-SHA256 token hashes at rest, Argon2id passwords,
  HttpOnly + SameSite=Strict cookies (Secure when HTTPS), CSRF double-submit bound to the session, rotation on
  login and step-up, server-side revocation and expiry (idle + absolute).
- Vite dev server **proxies** `/api` and `/ws` to the backend so cookies are same-origin (no permissive CORS).

---

## 3. Data model

`users`, `sessions`, `request_logs` (telemetry), `security_events`, `risk_assessments`, `simulation_runs`,
`simulation_steps`, `model_evaluations`, `policy_configs`, `auth_attempts`.

Required columns are those in v1 plus: `sessions.public_id` (non-secret reference shown in UI),
`sessions.baseline_device/network`, `sessions.protection_mode` (`sessionguard|traditional`, lab-only),
`sessions.is_lab`, `sessions.step_up_until`, `sessions.rotated_from_id`, `security_events.detection_method`,
`security_events.synthetic`, `request_logs.features` (JSON), `request_logs.conventional_decision`.

Indexes on every foreign key, `sessions.token_hash` (unique), `security_events.timestamp`, `request_logs.(session_id, ts)`.
Schema managed by Alembic.

---

## 4. Telemetry (Stage 1)

Per protected request the server records, **from its own observations**:
timestamp, session age, inter-request gap, request rate (10 s / 60 s), UA hash & parsed family/OS/device,
`Accept-Language`, client IP → /24 subnet → offline region table (RFC 5737 documentation ranges mapped to fictional
regions), endpoint category (page/data/sensitive/admin/auth), response status, auth failures, rotation/step-up/revocation.

**Spoofable vs. trustworthy** must be documented: UA, language and client hints are attacker-controlled;
the TCP peer address is reliable only without proxies; `X-Forwarded-For` is ignored.

**Synthetic signals** (OIDC token-exchange latency, BITM relay indicator, cookie-misuse indicator) are accepted only
from the harness and are flagged `synthetic` everywhere they appear.

---

## 5. Features (shared code path)

One pure function `extract_features(history, current, baseline) -> dict[str, float]` is used **both** by the runtime
and by the dataset generator. This guarantees train/serve parity. Features (20):

`session_age_min, log_gap_s, rate_10s, rate_60s, ua_mismatch, device_change_score, automation_ua,
subnet_change, region_change, distinct_contexts_5m, context_switches_5m, failed_auth_15m, authz_failures_5m,
sensitive_count_5m, sensitive_ratio_5m, seq_anomaly, admin_probe, token_exchange_ms*, relay_indicator*, cookie_misuse*`
(* synthetic, NaN when absent).

---

## 6. ML (Stage 2)

- **Generator**: seeded, scenario-based session simulator: `normal`, `benign_device_change`, `benign_network_change`,
  `token_replay` (incl. UA-copying attackers), `device_anomaly`, `network_anomaly`, `request_burst`, `bitm_relay`.
  Benign change scenarios exist specifically to measure false positives (RQ4).
- **Leakage controls**: `GroupShuffleSplit` by `session_id` (70/15/15); presence of synthetic features randomised
  independently of label; a **leave-one-attack-out** run that trains without `bitm_relay` and tests on it.
- **Models**: Rule-only detector, Logistic Regression, XGBoost, AutoEncoder+XGBoost (AE trained on benign traffic only;
  latent code + reconstruction error appended to features — *inspired by* AEXB, not a reproduction).
- **Metrics** (all computed, none hardcoded): accuracy, precision, recall, F1, confusion matrix, ROC-AUC, FPR,
  per-row inference latency (median/p95), attack-session detection latency (requests and seconds to first flag).
- Results are written to `ml/artifacts/metrics.json`, the `model_evaluations` table and `docs/RESULTS.md`.

---

## 7. Risk (Stage 3)

Each evidence source *i* produces strength `s_i ∈ [0,1]` and has a configurable weight `w_i ∈ [0,100]`.
Correlated sources are grouped (device: UA mismatch / device change / automation UA; network: subnet / region) and a
group contributes `max`, not sum. Fusion is noisy-OR:

```
instant = 100 · (1 − Π_i (1 − w_i·s_i/100))
```

Contributions are attributed proportionally to `w_i·s_i` so they sum to the score. The session score is
`max(instant, previous · decay)` — spikes apply immediately, recovery is gradual over clean requests.
A successful step-up re-baselines the context and resets the score (false-positive recovery).

Bands (demonstration defaults, not validated production thresholds): Low 0–24, Elevated 25–49, High 50–74, Critical 75–100.

---

## 8. Containment (Stage 4)

| Band | Non-sensitive request | Sensitive request |
|---|---|---|
| Low | allow | allow |
| Elevated | allow + `monitor` event | allow + monitor |
| High | allow | **403 `step_up_required`** until fresh password challenge |
| Critical | **revoke session (401)** or deny-sensitive (policy switch) | revoke |

Revocation is server-side, immediate and irreversible for that token. Step-up is a fresh password challenge
(explicitly *not* MFA) and rotates the token. Admin endpoints are role-gated; WebSockets require an admin session.

---

## 9. Demonstration surfaces

1. **Attack Simulation Lab** — 8 scenarios, each run step-by-step or end-to-end via real requests through the
   harness, with a live pipeline visualisation (Client A / Client B → Telemetry → ML → Risk → Containment).
2. **Presentation Mode** — guided 10-step story with Next/Previous/Pause/Run-all/Reset, an explanation panel,
   a live request/response inspector and a risk timeline. Every value comes from the backend.
3. **Experimental Comparison** — runs every scenario twice (traditional vs. SessionGuard) and charts accepted attacker
   requests, time-to-detect, containment and false positives.

---

## 10. Design system & motion spec

- Tokens: bg `#080D18`, surface `#111827`, elevated `#182235`, accent `#3B82F6`, cyan `#06B6D4`, success `#10B981`,
  warning `#F59E0B`, critical `#EF4444`. Borders are white at 6–10 % alpha; glass panels use `backdrop-blur` sparingly.
- Type: Inter (UI), JetBrains Mono (IDs, hashes, JSON, numbers in tables) with tabular numerals.
- Motion: 150–250 ms for UI feedback, 400–700 ms for data transitions, springs for gauges; `ease-out` for enter,
  `ease-in` for exit. Live-feed items enter with a 12 px slide + fade. **`prefers-reduced-motion` disables all
  non-essential animation.**
- Every control does something real; empty, loading and error states are designed, not default.
- Keyboard: `Ctrl/⌘+K` command palette, visible focus rings, `→/←/Space` drive Presentation Mode.

---

## 11. API

REST under `/api` (auth, sessions, security, simulation, ml, policy, portal) + `WS /ws/security-events`,
documented via OpenAPI at `/docs`. No endpoint returns placeholder data. Tokens never appear in responses,
logs or WebSocket frames (only `public_id` and an 8-char hash fingerprint).

---

## 12. Tooling

`setup.ps1` (verify toolchain → venv → deps → migrate → seed → generate dataset → train → evaluate → write RESULTS.md
→ build check) and `start.ps1` (start backend + frontend, wait for `/api/health`, print URLs, open browser, actionable errors).

---

## 13. Definition of done (must all pass)

Automated (`pytest`):
- Auth: login ok, bad password, expired, revoked, logout, unauthenticated, role gate.
- Session: rotation on login & step-up, CSRF required for cookie POSTs, isolation between users, revocation sticks.
- Detection: normal stays Low; device change and network change raise risk proportionally; burst raises risk;
  replay from a second context reaches Critical and is revoked; benign change recovers after step-up.
- ML: dataset generation is deterministic for a seed; training produces loadable artifacts; inference handles NaN;
  metrics are computed from predictions.
- E2E: login → admin sees session → replay → event recorded → risk rises → containment → revoked token gets 401 →
  dashboard event exists → comparison shows traditional accepted / SessionGuard contained → reset → repeatable.

Manual: `setup.ps1` then `start.ps1` on a clean Windows 11 machine; the 5-minute script in `DEMO_GUIDE.md` works offline.

---

## 14. Honesty rules

No fabricated metrics, citations, detections or claims of reproducing published methods. Synthetic data and synthetic
signals are labelled wherever shown. Limitations are documented (single-node, synthetic dataset, metadata can be
spoofed, password re-check is not MFA, thresholds are not empirically calibrated).
