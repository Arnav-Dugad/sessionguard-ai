# SessionGuard AI — Five-Minute Demonstration Guide

A tight script for a live evaluation. Total time ~5 minutes. Everything uses real backend requests and
actual application state — nothing is pre-animated.

> **Before you start:** run `.\setup.ps1` once, then `.\start.ps1`. The browser opens at
> http://localhost:5173. Have it on the login screen. If anything looks stale, open **System Settings →
> Reset lab**.

---

## 0:00 — Frame the problem (30s)

> "A stolen session token is a *valid* token. Conventional checks — exists, not expired, not revoked —
> accept it every time, and MFA doesn't help because the attacker replays an already-authenticated
> session. SessionGuard asks a second question on every request: does this request's *context* match the
> session's behaviour?"

Sign in as **admin** / `Admin-SOC!2027`. The **Overview** console appears with live figures.

**Point out:** active sessions, average risk, the active model (AutoEncoder + XGBoost), detection
latency, and the live event feed updating in real time over a WebSocket.

---

## 0:45 — The core attack (90s)

Go to **Attack Simulation Lab** → select **Controlled Token Replay** → press **Run full**.

Narrate as the pipeline animates (Clients → Telemetry → ML Detection → Risk Scoring → Containment):

> "A legitimate user logs in and browses — risk stays Low. The harness copies the valid token to a
> second client in another region on a different browser. Conventional validation would accept it. But
> now the same token is alternating between two contexts — the replay signature. Risk climbs, the ML
> model flags the anomaly, and at Critical the containment engine **revokes the session server-side**."

**Point at the outcome panel:** peak risk ~79 (Critical), *attacker accepted 0*, *attacker blocked 4*,
*revoked: yes*, and the final step where the retried token returns **401**.

---

## 2:15 — Prove it's real, not a UI trick (45s)

Flip the mode toggle to **Traditional**, press **Run full** again.

> "Same scenario, conventional validation only. Every attacker request is accepted — the token is valid.
> This is the gap SessionGuard closes."

**Point out:** *attacker accepted* is now non-zero, *revoked: no*.

---

## 3:00 — The measured comparison (45s)

Go to **Experimental Comparison** → **Run all attacks**.

> "This runs every attack scenario through both systems and charts the result. Traditional validation
> accepts the attacker's valid-token requests across the board; SessionGuard contains them. These bars
> are computed from the runs you just saw — not hardcoded."

---

## 3:45 — The ML is honest (45s)

Go to **ML Model Evaluation**.

> "Four detectors, evaluated on held-out *sessions* — split by group so there's no leakage. The rule
> baseline is deliberately high-precision, low-recall; XGBoost lifts recall to ~0.96 F1. That improvement
> is research question RQ2, measured — and there's a leave-one-attack-out test for generalisation."

**Point out:** the comparison table, the best-F1 badge, feature importances.

---

## 4:30 — The usability trade-off (30s)

Go to **Attack Simulation Lab** → **False Positive & Recovery** → **Run full**.

> "A genuine user who travels and switches to their phone looks a lot like an attacker. SessionGuard
> doesn't lock them out — it *challenges* the sensitive action with a password step-up, re-establishes
> trust, and clears the risk. That's RQ4: the false-positive trade-off, handled gracefully."

---

## Closing line

> "Four stages — telemetry, ML detection, continuous risk, automated Zero-Trust containment — in one
> working system, running entirely offline on this laptop, with every claim backed by a test suite."

---

## Alternative: guided Presentation Mode

If you'd rather have the story paced for you, open **Presentation Mode** and press **Run full**. It
walks all 11 narrative steps of the replay-and-containment story automatically, with a live risk gauge
and event feed, each step driven by a real backend request.

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| Numbers look stale / sessions piled up | **System Settings → Reset lab**, or re-run the scenario |
| "Model: rule-only" on Overview | models not trained — run `.\scripts\train_models.ps1`, then **Settings → Reload models** |
| A scenario won't start | press **Reset** in the Lab, then **Start/Run full** again |
| Backend not responding | re-run `.\start.ps1`; check nothing else uses port 8000 |
| Want a clean slate | stop services, delete `backend/data/sessionguard.db*`, re-run `.\setup.ps1 -SkipTrain` |

## What to have open in tabs

1. Overview · 2. Attack Simulation Lab · 3. Experimental Comparison · 4. ML Model Evaluation ·
5. Presentation Mode (backup). The **User Portal** (sign in as `ada` in a second browser profile) is a
nice optional aside to show the attack target and the step-up challenge from the user's side.
