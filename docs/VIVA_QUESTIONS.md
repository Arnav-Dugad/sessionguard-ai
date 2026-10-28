# SessionGuard AI — Viva Questions & Answers

Thirty-plus questions an evaluator is likely to ask, with concise, defensible answers. Answers reflect
what the system *actually* does.

## Concepts

**1. What is session hijacking?**
Taking over a legitimate user's authenticated session by obtaining its session identifier (token/cookie)
and presenting it as your own. Because the token already represents a completed authentication, the
attacker inherits the user's access without knowing their password.

**2. How do cookies and session tokens work here?**
On login the server generates a 256-bit random token and stores only its HMAC-SHA256 hash. The raw token
is sent to the browser in an HttpOnly, SameSite=Strict cookie. On each request the browser sends the
cookie; the server hashes it and looks up the server-side session. Nothing sensitive is stored client-side.

**3. What is token replay?**
Re-sending a valid session token from a different client/context than the one it was issued to. The token
is cryptographically valid, so conventional validation accepts it — which is exactly why context-based
detection is needed.

**4. Why doesn't MFA prevent reuse of an already-authenticated bearer token?**
MFA gates the *authentication event*. Once authentication succeeds, the resulting session token is a
bearer credential — whoever presents it is treated as the user. An attacker replaying the token never
re-triggers MFA, so MFA alone doesn't stop session reuse.

**5. What is Zero Trust?**
"Never trust, always verify." Every request is authenticated and authorized on its own merits rather than
trusting a network perimeter or a one-time login. Here it means re-evaluating risk and applying a policy
decision on *every* protected request.

**6. What is continuous authentication?**
Instead of authenticating once, the system continuously re-verifies that the active session still behaves
like the legitimate user, and can demand re-verification (step-up) when confidence drops.

**7. What is a false positive, and why does it matter?**
Flagging legitimate activity as malicious. It matters because over-blocking (e.g., when a user simply
travels or changes devices) destroys usability and trust. We measure FPR and use proportional responses
plus step-up recovery instead of hard lockouts (RQ4).

## Machine learning

**8. Why XGBoost?**
It's a strong, fast gradient-boosted tree model for tabular data with mixed-scale features, handles
non-linear interactions and missing values, trains in seconds on CPU, and gives feature importances — a
good fit for per-request scoring on a laptop.

**9. What is an AutoEncoder and how is it used here?**
A neural network trained to reconstruct its input through a narrow bottleneck. Trained on **benign**
traffic only, it learns "normal"; anomalous requests reconstruct poorly (high error). We feed its latent
code and reconstruction error, alongside the raw features, into XGBoost — the AEXB-inspired model.

**10. Is this a reproduction of the published AEXB model?**
No. It's *inspired by* that architecture. The data, preprocessing and hyper-parameters differ, so we
report it as an adaptation, not a reproduction.

**11. How do you prevent data leakage in evaluation?**
We split by **session group** (GroupShuffleSplit, 70/15/15) so no session appears in more than one split;
the presence of synthetic features is randomised independently of the label; and a leave-one-attack-out
run trains with an entire attack family removed and tests on it.

**12. How do you know the ML actually helps (RQ2)?**
The rule baseline and the ML models are evaluated on the same held-out sessions. The rule detector is
high-precision but low-recall at the 0.5 threshold; XGBoost/AEXB lift F1 substantially (see
`docs/RESULTS.md`). The lift is the evidence.

**13. Are the accuracy numbers hardcoded?**
No. Every metric is computed from held-out predictions by `ml/training/train.py` and written to
`metrics.json`, `docs/RESULTS.md` and the `model_evaluations` table. Delete the artifacts and re-run to
regenerate them.

**14. Why is the dataset synthetic, and what are the limits?**
No suitable labelled real-world session-hijacking dataset is available offline, and using real sessions
would be unethical. The generator reuses the exact runtime feature extractor so the distribution matches
serving — but absolute metrics describe the generator, not the real world. We state this limitation.

**15. What are the 20 features?**
Session age, inter-request gap, request rates (10s/60s), UA mismatch, device-change score, automation-UA
flag, subnet/region change, distinct contexts and context switches in 5 min, failed auth (15 min),
authz failures, sensitive count/ratio, sequence anomaly, admin probing, and three *synthetic* signals
(token-exchange ms, relay indicator, cookie-misuse).

## Risk & containment

**16. How is the risk score calculated?**
Each evidence source yields a strength ∈ [0,1] with a configurable weight. They're fused with noisy-OR:
`100·(1 − Π(1 − wᵢ·sᵢ/100))`, bounded to 0–100. Contributions are attributed proportionally so they sum
to the score; correlated signals are grouped to avoid double-counting; the score decays over clean
activity.

**17. Why noisy-OR instead of just adding points?**
Addition can exceed 100 and double-counts correlated evidence. Noisy-OR saturates — many weak signals
raise risk without overflowing — and models "any strong independent signal is already alarming."

**18. What are the risk bands and are they validated?**
Low 0–24, Elevated 25–49, High 50–74, Critical 75–100. They're demonstration defaults, **not**
empirically calibrated production thresholds, and are editable in the Policy Manager.

**19. What does containment actually do?**
Policy maps band + sensitivity to an action: allow, monitor, step-up (fresh password challenge on a
sensitive action), or revoke (server-side). Revocation flips session state so every client holding the
token is rejected.

**20. How does session revocation work — is it just hidden in the UI?**
No. Revocation sets server-side session state; the pipeline rejects the token with 401 on the *next*
request from any client. The end-to-end test and the `revocation` scenario prove the revoked token stays
rejected.

**21. What is the step-up challenge — is it MFA?**
It's a fresh **password** re-check that rotates the token and re-baselines trust. We explicitly call it a
password challenge, *not* MFA. WebAuthn/TOTP are future work.

**22. Could an attacker just send a low risk value to bypass detection?**
No. Risk is computed server-side from server-observed telemetry on every request. The client never
supplies a risk value, and spoofable headers like `X-Forwarded-For` are ignored.

## Security engineering

**23. How are passwords stored?**
Argon2id (memory-hard) with per-password salts. Plaintext is never stored or logged. Login also pays the
hashing cost for unknown users to reduce timing side-channels.

**24. How are session tokens protected at rest?**
Only an HMAC-SHA256 hash (keyed by a server pepper) is stored, so a leaked database can't be used to forge
cookies. The raw token exists only in the HttpOnly cookie; the UI shows a short non-secret fingerprint.

**25. How is CSRF handled?**
A double-submit token derived from the session (`HMAC(csrf_secret, token_hash)`), required on all
cookie-authenticated unsafe methods. Because it's bound to the session, rotating the session rotates the
CSRF token.

**26. Why are device and network signals "not proof"?**
User-Agent, language and client hints are fully client-controlled and trivially spoofable; the TCP peer
address is reliable only without an intermediary proxy. So they're corroborating evidence, fused with
other signals — never a sole basis for revocation. A device change alone never auto-revokes (see the
`device_anomaly` scenario).

**27. How does the lab run attacks without touching real systems?**
Lab clients are `httpx.AsyncClient`s bound to the app via `ASGITransport`. Requests traverse the full
pipeline but open no sockets and can't reach any external host. The simulated client address is set at the
transport layer, and a signed virtual clock (harness-only) makes timing realistic.

**28. Are the synthetic BITM/OIDC signals presented as real?**
No. They're injected only by the harness (authenticated with a per-process secret) and tagged
`synthetic=true` in every event, the UI and the database.

## Positioning & limits

**29. How is this different from existing approaches?**
The reviewed studies each address a piece — JWT trust scoring, OIDC timing, cookie protection, AEXB
detection, continuous auth, Zero-Trust. This project **integrates** telemetry + ML + continuous risk +
automated containment into one evaluated, working pipeline, which the survey identifies as the gap.

**30. What are the main limitations?**
Single-node SQLite demo; synthetic dataset; spoofable metadata; step-up is a password re-check, not MFA;
thresholds aren't empirically calibrated; the AEXB model is adapted, not reproduced. All are stated in the
README and the Research Mapping.

**31. What would you do next with more time?**
Real WebAuthn/TOTP step-up; behavioural biometrics; validation on a real-world dataset; empirical
threshold calibration; a faithful AEXB reproduction; production hardening (Postgres, rate limiting,
horizontal scale).

**32. Can the whole demo be reset and repeated?**
Yes — **System Settings → Reset lab** revokes lab sessions and clears in-memory runs; every scenario is
idempotent and can be re-run, and the end-to-end test asserts repeatability.
