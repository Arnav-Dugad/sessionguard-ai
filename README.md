<div align="center">

# 🛡️ SessionGuard AI

### Intelligent Session-Hijacking Detection · Behavioral Authentication · Automated Zero-Trust Defense

**Detect. Analyze. Contain. Protect.**

*A fully working, offline-capable security operations platform that detects and contains the reuse of a valid session token — built for a live academic demonstration on a single Windows 11 laptop.*

</div>

---

## The one-sentence pitch

> **Can the reuse of a technically valid session token be detected and contained automatically?**
> SessionGuard AI answers *yes*, with measured evidence: it fuses per-request telemetry, ML anomaly
> detection and continuous risk scoring to drive automated Zero-Trust containment — revoking a
> compromised session **server-side**, not just hiding it in the UI.

This is **not** a mockup. Every button does something real, every number is computed from stored
application data, and the headline claim is backed by an automated test suite and a reproducible
ML evaluation.

---

## Why this is different

A stolen session token is a *valid* token. Conventional validation — "does it exist, is it expired,
has it been revoked?" — accepts it every time. Even MFA doesn't help: the user already passed MFA, and
the attacker is replaying the *result* of that authentication.

SessionGuard AI adds a second question on **every request**: *does this request's context match the
session's established behaviour?* It runs a four-stage pipeline and acts on the answer.

```
   ┌─────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐
   │  Stage 1    │   │   Stage 2    │   │    Stage 3    │   │     Stage 4      │
   │  Telemetry  │──▶│ ML Detection │──▶│ Risk Scoring  │──▶│ Zero-Trust       │
   │ (20 feats)  │   │ rules+XGB+AE │   │ noisy-OR 0-100│   │ Containment      │
   └─────────────┘   └──────────────┘   └───────────────┘   └──────────────────┘
      per request      prob. of anomaly   explainable score   allow→monitor→
                                                              step-up→revoke
```

---

## Quick start (Windows 11)

```powershell
# 1. One-time setup: venv, deps, database, seed accounts, dataset, train + evaluate models
powershell -ExecutionPolicy Bypass -File .\setup.ps1

# 2. Start backend + frontend and open the browser
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Then open **http://localhost:5173** and sign in:

| Account | Password | Role |
|---|---|---|
| `admin` | `Admin-SOC!2027` | SOC administrator — full console |
| `ada`   | `Demo-User!2027` | Standard user — Helios Vault portal |
| `grace` | `Demo-User!2027` | Standard user |

> All identities and data are fictional. Everything runs locally and offline after setup — no cloud,
> no paid APIs, no external database.

**URLs:** app `http://localhost:5173` · API `http://localhost:8000` · API docs `http://localhost:8000/docs`

---

## The 5-minute demo

1. Sign in as **admin** → the **Overview** console lights up with live data.
2. Open **Attack Simulation Lab** → select **Controlled Token Replay** → press **Run full**.
3. Watch the pipeline: a second client replays the *same valid token* from a different device and
   region. Conventional validation would accept it; SessionGuard's risk climbs past **Critical** and
   the session is **revoked server-side**. The retried token returns **401**.
4. Switch the mode toggle to **Traditional** and run it again — the attacker's requests are all accepted.
5. Open **Experimental Comparison → Run all attacks** for the side-by-side numbers, and **ML Model
   Evaluation** for the measured detection metrics.

A full script is in [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md).

---

## What's inside

### Security operations console (admin)
Overview · Active Sessions · Threat Detection · **Attack Simulation Lab** · Live Security Events ·
Risk Analytics · ML Model Evaluation · Zero-Trust Policy Manager · Experimental Comparison ·
**Presentation Mode** · System Settings.

### User portal (Helios Vault)
A realistic protected app — login, profile, documents, balance, sensitive actions, active-session
management and step-up re-authentication — so the attack scenarios have something real to defend.

### The eight lab scenarios
`normal` · `token_replay` · `device_anomaly` · `network_anomaly` · `request_burst` · `revocation` ·
`false_positive` · `bitm` (synthetic). Each runs **real HTTP requests** through the complete pipeline
via an in-process harness — see [How the lab stays honest](#how-the-lab-stays-honest).

---

## Architecture at a glance

| Layer | Tech |
|---|---|
| Frontend | React 19 · TypeScript · Vite · Tailwind CSS v4 · Framer Motion · Recharts · TanStack Query |
| Backend | Python 3.12+ · FastAPI · SQLAlchemy 2 · Pydantic v2 · SQLite (WAL) · WebSockets |
| ML | scikit-learn · XGBoost · NumPy · Pandas (CPU only, no GPU required) |
| Security | Argon2id · HMAC-SHA256 token hashes · HttpOnly+SameSite cookies · session-bound CSRF · rotation · server-side revocation |

Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### The four stages

1. **Telemetry** — 20 server-observed features per request (session age, request rate, device/UA
   consistency, network/region change, concurrent-context use, auth failures, sensitive activity, plus
   optional *clearly-labelled synthetic* OIDC/BITM signals). One `extract_features` function is shared
   by the runtime and the dataset generator, guaranteeing train/serve parity.
2. **ML detection** — a transparent rule baseline, Logistic Regression, XGBoost, and an
   AutoEncoder+XGBoost model *inspired by* the AEXB architecture from the literature (the AE learns
   "normal" from benign traffic; its latent code + reconstruction error feed XGBoost).
3. **Risk scoring** — evidence fused with **noisy-OR** into a bounded 0–100 score, with each factor's
   contribution attributed proportionally, correlated signals grouped to avoid double-counting, and
   decay/recovery over time. Fully explainable.
4. **Zero-Trust containment** — `allow → monitor → step-up → revoke`, sensitivity-aware, enforced on
   the backend. A correct step-up password challenge re-baselines trust and clears the score.

---

## Machine learning

```powershell
# Reproducible: fixed seed, group-split by session (no leakage), leave-one-attack-out generalisation test
.\scripts\train_models.ps1 -Seed 42
```

- **No leakage:** sessions are split by group (70/15/15) so no session spans splits; the presence of
  synthetic features is randomised independently of the label; a leave-one-attack-out run tests on an
  attack family removed from training.
- **No invented numbers:** all metrics are computed from held-out predictions and written to
  [`docs/RESULTS.md`](docs/RESULTS.md) and the `model_evaluations` table.
- **Honest baseline:** the rule detector is deliberately high-precision / low-recall at the 0.5
  threshold; the ML models lift recall substantially — this is exactly research question **RQ2**.

See the live numbers on the **ML Model Evaluation** page and in `docs/RESULTS.md`.

---

## How the lab stays honest

Running an "attack from a different device and network" on `localhost` is impossible without spoofing.
Instead of faking it, the lab uses a disciplined in-process harness:

- Each lab client is an `httpx.AsyncClient` bound to the FastAPI app through `ASGITransport`. Requests
  travel the **entire** middleware/routing/pipeline stack, but **no network socket is opened and no
  other host can be reached** — so the demo can never touch a real third party.
- The simulated client address is set at the **transport layer** (the server sees it as the TCP peer),
  so detection never relies on spoofable headers like `X-Forwarded-For`.
- A **signed virtual clock** lets a "request burst" really be bursty and a "return next session" really
  be minutes later, even though the whole scenario runs in well under a second. Only harness requests
  (authenticated by a per-process secret that never leaves memory) may use it or inject synthetic signals.
- Every synthetic signal is tagged `synthetic=true` wherever it appears — in events, the UI and the DB.

This is why the project can claim the scenarios are real backend behaviour without overclaiming.

---

## Project layout

```
sessionguard-ai/
├── backend/app/        FastAPI app: auth, telemetry, detection, risk, containment, simulation, api, websocket
├── backend/tests/      pytest suite (auth, sessions, detection, ML, end-to-end acceptance)
├── frontend/src/       React SPA: 12 pages, design system, charts, live feed
├── ml/                 datasets/ (generator) · training/ · evaluation/ · artifacts/ (models + metrics)
├── scripts/            train_models.ps1 · run_tests.ps1
├── docs/               ARCHITECTURE · DEMO_GUIDE · RESEARCH_MAPPING · RESULTS · VIVA_QUESTIONS
├── setup.ps1           one-time setup          start.ps1   run both services
└── requirements.txt    package.json
```

---

## Testing

```powershell
.\scripts\run_tests.ps1        # or:  .venv\Scripts\python -m pytest backend
```

44 tests cover authentication, session security (rotation, CSRF, revocation, isolation), the detection
and risk layers, the ML pipeline (deterministic generation, inference, NaN handling), and the full
end-to-end acceptance workflow (login → replay → detect → score → contain → revoked token rejected →
dashboard records it → comparison → repeatable).

---

## Limitations (stated plainly)

- Single-node demonstration on SQLite; not hardened for production or multi-tenant scale.
- The dataset is **synthetic**; absolute metrics describe this generator, not real-world traffic.
- Device, User-Agent and language telemetry is **client-controlled and spoofable** — it is corroborating
  evidence, never proof. The TCP peer address is reliable only without an intermediary proxy.
- Step-up is a **password re-check, not multi-factor authentication** (WebAuthn/TOTP are future work).
- Risk thresholds are demonstration defaults, **not** empirically calibrated production values.
- The AutoEncoder+XGBoost model is *inspired by* the published AEXB architecture, not a faithful
  reproduction (different data, preprocessing and hyper-parameters).

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design, pipeline, session lifecycle, data flow
- [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) — the five-minute presentation script
- [`docs/RESEARCH_MAPPING.md`](docs/RESEARCH_MAPPING.md) — implementation ↔ literature survey
- [`docs/RESULTS.md`](docs/RESULTS.md) — auto-generated evaluation metrics
- [`docs/VIVA_QUESTIONS.md`](docs/VIVA_QUESTIONS.md) — 30+ Q&A for the evaluation
- [`docs/MASTER_PROMPT_v2.md`](docs/MASTER_PROMPT_v2.md) — the tightened build specification this was built against

---

<div align="center">
<sub>Built for an academic cybersecurity demonstration. Authorized, local, synthetic data only.</sub>
</div>
