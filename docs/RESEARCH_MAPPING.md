# SessionGuard AI — Research Mapping

How the implementation relates to the literature survey. This map is deliberately honest about what is
**directly implemented**, **adapted**, **simulated**, or **future work** — no paper's full methodology is
claimed to be reproduced.

> ⚠️ The literature-survey document was not supplied to the build environment, so the citations below are
> reproduced from the project brief. **Verify author names, years and exact claims against your actual
> `Session_Hijacking_Literature_Survey.docx` before submission** and correct any discrepancy here.

## Research questions

| RQ | Question | Where it is answered |
|---|---|---|
| **RQ1** | Can session telemetry distinguish controlled replay from normal activity? | Lab scenarios `normal` vs `token_replay`; the 20-feature telemetry layer; **Experimental Comparison** |
| **RQ2** | Does ML-assisted risk scoring improve detection over a rule-only baseline? | **ML Model Evaluation** + `docs/RESULTS.md`: rule F1 vs XGBoost/AEXB F1 on held-out sessions |
| **RQ3** | Can automated containment reduce the window of unauthorized reuse? | `revocation` + `token_replay` scenarios; containment latency; revoked-token-rejected test |
| **RQ4** | What false-positive trade-offs arise from device/network changes? | `false_positive`, `benign_*` dataset classes, measured FPR, step-up recovery |

## Study → implementation map

| Study (per brief) | Contribution | In SessionGuard AI | Fidelity |
|---|---|---|---|
| **Bucko et al. (2023)** | Behavior-weighted JWT trust scoring | Continuous 0–100 risk score with weighted, explainable evidence fusion and decay | **Adapted** — same idea (behavioural trust weighting), different mechanism (noisy-OR over our own features, not JWT claims) |
| **Han & Lee (2023)** | OIDC token-exchange timing as a risk signal | `token_exchange_ms` synthetic feature + evidence source in the `bitm` scenario | **Simulated** — injected telemetry, clearly labelled; no real OIDC provider |
| **Shi, Ma & Wang (2025)** | Cookie misuse / XSS-related protection | HttpOnly+SameSite cookies, session-bound CSRF, `cookie_misuse` synthetic indicator | **Partially implemented** (cookie hardening) + **simulated** (the indicator feature) |
| **Kandasamy & Roseline (2025)** | AutoEncoder + XGBoost (AEXB) detection | `AutoEncoderXGB`: AE trained on benign traffic, latent + reconstruction error → XGBoost | **Inspired by** — architecture echoed, *not* a faithful reproduction (different data, preprocessing, hyper-parameters) |
| **Baig, Eskeland & Yang (2023)** | Continuous authentication / re-verification | Per-request re-evaluation + risk-based step-up re-authentication | **Adapted** — continuous verification via step-up password challenge (not full behavioural biometrics) |
| **Gambo & Almulhem (2025)** | Zero-Trust architecture | Policy-driven `allow → monitor → step-up → revoke` containment, "never trust, always verify" per request | **Adapted** — a practical subset of Zero-Trust applied to session validation |

## The identified research gap

The brief identifies that, among the reviewed studies, there is no evaluated system that **combines**
(1) session/traffic telemetry, (2) ML anomaly detection, (3) continuous behavioural risk scoring, and
(4) automated Zero-Trust containment in one pipeline. SessionGuard AI implements all four stages in a
single working application and measures the result — that integration is the contribution.

## Honesty ledger

**Directly implemented:** server-side session management, Argon2id + HMAC token hashing, rotation, CSRF,
server-side revocation + expiry, 20-feature telemetry, rule-based detection, noisy-OR risk scoring,
Zero-Trust containment, step-up re-auth, four trained ML models with leakage-controlled evaluation,
live SOC dashboard, eight real-request lab scenarios, experimental comparison.

**Adapted from the literature:** behaviour-weighted trust scoring, continuous verification, Zero-Trust
containment, the AEXB-style AutoEncoder+XGBoost model.

**Simulated (labelled):** OIDC token-exchange timing, BITM relay indicators, cookie-misuse indicator —
injected by the lab harness only and tagged `synthetic` everywhere.

**Future work:** WebAuthn/TOTP step-up (true MFA); real behavioural biometrics; validation on a
real-world dataset; empirical threshold calibration; multi-node/production hardening; a faithful AEXB
reproduction with the original dataset and preprocessing.
