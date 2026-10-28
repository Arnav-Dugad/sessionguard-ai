# SessionGuard AI — Architecture

## 1. System overview

```
                         Browser (React SPA, :5173)
                                   │  cookies (HttpOnly session + readable CSRF), same-origin
                                   │  Vite dev proxy → :8000
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          FastAPI backend (:8000)                               │
│                                                                                │
│  API routers ── auth · sessions · portal · security · simulation · experiment  │
│                 · ml · policy · ws                                              │
│        │                                                                       │
│        ▼                                                                       │
│  protected() dependency  ──►  four-stage pipeline (per protected request)      │
│        │                                                                       │
│        ├─ Stage 1  Telemetry   (app/telemetry)                                 │
│        ├─ Stage 2  Detection   (app/detection: rules + ML)                     │
│        ├─ Stage 3  Risk        (app/risk: noisy-OR fusion)                     │
│        └─ Stage 4  Containment (app/containment: allow/monitor/step-up/revoke) │
│        │                                                                       │
│        ▼                                                                       │
│  SQLAlchemy models ◄──► SQLite (WAL)         EventHub ──► WebSocket subscribers │
└──────────────────────────────────────────────────────────────────────────────┘
                                   ▲
                                   │  in-process ASGITransport (no sockets)
                         Attack Simulation Lab harness
```

The frontend is a single-page app. The Vite dev server proxies `/api` and `/ws` to FastAPI, so the
browser treats the app and API as same-origin — session cookies stay first-party and no permissive
CORS is needed.

## 2. The four-stage pipeline

Implemented in [`backend/app/containment/pipeline.py`](../backend/app/containment/pipeline.py).
A route opts in with `Depends(protected("<category>"))`. Categories (`page`, `data`, `sensitive`,
`admin`, `console`) drive sensitivity-aware decisions.

### Stage 0 — conventional validation (always first)
Exists? Not revoked? Not expired (idle + absolute)? CSRF valid for unsafe methods? Role allowed?
A **traditional-mode** session stops here — this is the baseline the project compares against.

### Stage 1 — telemetry (`app/telemetry`)
From the server's own observations: timestamp, session age, inter-request gap, request rate (10s/60s),
parsed User-Agent (browser/OS/device/automation), `Accept-Language`, client IP → /24 subnet → offline
region, endpoint category, response status, auth failures. Optional synthetic signals (OIDC token-
exchange latency, BITM relay indicator, cookie-misuse) are accepted **only** from the harness and are
flagged `synthetic`.

`extract_features(history, current, baseline)` produces the 20-feature vector and is the **single**
feature implementation used by both the runtime and the dataset generator (train/serve parity).

### Stage 2 — detection (`app/detection`)
- **Rules** (`rules.py`): map features to evidence sources each with a strength ∈ [0,1]. Correlated raw
  features are folded into one source (max), so "UA changed" and "browser changed" never double-count.
- **ML** (`ml_detector.py`, `ml_models.py`): the active model returns P(anomaly). If no model is loaded,
  the detector reports unavailable and the system falls back to rules — it never invents a probability.

### Stage 3 — risk (`app/risk`)
Evidence (rules + an ML evidence item gated by an operating floor) is fused with **noisy-OR**:

```
instant = 100 · (1 − Πᵢ (1 − wᵢ·sᵢ/100))
```

Bounded to [0,100], saturating instead of over-counting. Each source's points are attributed in
proportion to `wᵢ·sᵢ`, so the displayed contributions sum to the score. The session score is
`max(instant, decayed_previous)` — spikes apply at once, recovery is gradual. A successful step-up
re-baselines context and resets the score.

### Stage 4 — containment (`pipeline.decide`)

| Band (0–100) | Non-sensitive | Sensitive |
|---|---|---|
| Low 0–24 | allow | allow |
| Elevated 25–49 | allow + monitor | allow + monitor |
| High 50–74 | allow | **step-up (403)** |
| Critical 75–100 | **revoke (401)** / deny | **revoke (401)** |

Revocation flips server-side state; every client holding the token is then rejected. Enforcement can be
switched to **monitor-only** (decisions logged, not applied) from the Policy page.

## 3. Session lifecycle

```
register ──► login ──► [token issued, baseline set] ──► protected requests (pipeline) ──┐
                 │                                                                       │
                 │ rotation on login (fixation defence)         risk rises ──────────────┤
                 ▼                                                                       ▼
            step-up challenge ◄──────────── High + sensitive            Critical ──► REVOKED (401)
                 │ correct password                                                      │
                 ▼                                                                        ▼
        [token rotated, baseline reset, risk 0]                              idle/absolute ──► EXPIRED
```

- Tokens: 256-bit `secrets.token_urlsafe`; only an **HMAC-SHA256 hash** (server pepper) is stored. The
  raw token lives only in the HttpOnly cookie. A short non-secret fingerprint is shown in the UI.
- CSRF: double-submit token derived from the session (`HMAC(csrf_secret, token_hash)`), so rotating the
  session rotates the CSRF token. Required on all cookie-authenticated unsafe methods.
- Revocation and expiry are enforced on **every** request; a revoked token never regains access.

<a name="trust"></a>
## 4. What is trustworthy vs spoofable

| Signal | Source | Trust |
|---|---|---|
| Session token validity | server-side hash lookup | **trustworthy** |
| TCP peer address | transport | trustworthy *without* an intermediary proxy |
| `X-Forwarded-For` | client header | **ignored** (spoofable) |
| User-Agent / device | client header | corroborating only — spoofable |
| `Accept-Language` | client header | corroborating only — spoofable |
| Synthetic OIDC/BITM signals | lab harness | **simulated**, always tagged `synthetic` |

Security decisions never trust a client-supplied risk value; the server recomputes risk every request.

## 5. Data flow & persistence

`users`, `sessions`, `request_logs` (telemetry), `security_events`, `risk_assessments`, `auth_attempts`,
`simulation_runs`, `simulation_steps`, `model_evaluations`, `policy_configs`. Indexed on every foreign
key and on hot paths (`sessions.token_hash` unique, `request_logs.(session_id, ts)`,
`security_events.timestamp`). SQLite runs in WAL mode.

Security events are recorded through one recorder, flushed to the DB, then broadcast to admin WebSocket
subscribers via an in-process `EventHub` (thread-safe hand-off to the event loop). No token value ever
appears in an event, log or WebSocket frame.

## 6. The simulation harness

See README → *How the lab stays honest*. Key point: `httpx.ASGITransport` runs requests through the real
app with the client address set at the transport layer and a signed virtual clock, so scenarios are
genuine backend behaviour that cannot reach any external host.
