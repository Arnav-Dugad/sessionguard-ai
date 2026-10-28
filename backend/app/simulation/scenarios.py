"""Declarative definitions of the eight lab scenarios.

Each scenario is a list of steps. A step names the client, the action, the virtual-time
advance (so a "burst" really is many requests close together on the virtual clock, and a
"return next day" really is hours later) and an explanation shown in the UI. The runner in
``runner.py`` turns these into real HTTP requests through the harness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["login", "get", "post", "replay_adopt", "reauth", "retry_revoked", "note"]


@dataclass
class Step:
    title: str
    action: Action
    client: str = "laptop"
    path: str = ""
    method: str = "GET"
    advance_s: float = 2.0
    repeat: int = 1
    body: dict[str, Any] | None = None
    synthetic: dict[str, float] | None = None
    malicious: bool = False
    source_client: str | None = None  # for replay_adopt
    password: str | None = None
    explanation: str = ""
    expect: str = ""  # human-readable expected outcome


@dataclass
class Scenario:
    key: str
    name: str
    tagline: str
    icon: str
    category: str
    threat_level: str  # none | low | medium | high | critical
    rq: list[str]
    summary: str
    clients: list[str]
    steps: list[Step] = field(default_factory=list)
    teaches: str = ""


LOGIN = lambda client="laptop", adv=1.0: Step(  # noqa: E731
    "Authenticate", "login", client=client, advance_s=adv, password="use-default",
    explanation="The demo user signs in. The server issues a fresh random token, stores only its HMAC hash, "
                "and records the device + network as the session's trust baseline.",
    expect="200 · session created · risk 0 (Low)")


def _normal_browse(client: str = "laptop") -> list[Step]:
    return [
        Step("Load dashboard", "get", client=client, path="/api/portal/dashboard", advance_s=3,
             explanation="A normal authenticated page load. Telemetry is collected and a risk assessment runs.",
             expect="200 · risk stays Low"),
        Step("List documents", "get", client=client, path="/api/portal/documents", advance_s=8,
             explanation="Ordinary navigation at human pace keeps every behavioural feature in its normal range.",
             expect="200 · risk stays Low"),
        Step("Open a document", "get", client=client, path="/api/portal/documents/1", advance_s=12,
             explanation="Reading a document. Device and network still match the baseline.", expect="200 · risk stays Low"),
    ]


SCENARIOS: dict[str, Scenario] = {}


def _add(s: Scenario) -> None:
    SCENARIOS[s.key] = s


_add(Scenario(
    "normal", "Normal Session", "Authorized activity from the trusted baseline", "ShieldCheck", "baseline", "none",
    ["RQ1", "RQ4"],
    "Establishes the ground truth: legitimate, same-device, same-network activity must stay in the Low band and never "
    "trigger containment. Everything else is measured against this.",
    ["laptop"],
    [LOGIN(), *_normal_browse(),
     Step("Export data (sensitive)", "post", client="laptop", path="/api/portal/export", advance_s=10,
          explanation="Even a sensitive action is allowed without friction because the context matches the baseline and "
                      "risk is Low.", expect="200 · allowed, no step-up")],
    teaches="What 'normal' looks like to every feature and why it must not alarm."))

_add(Scenario(
    "token_replay", "Controlled Token Replay", "A valid token reused from a second client context", "Copy", "replay", "critical",
    ["RQ1", "RQ2", "RQ3"],
    "The core demonstration. A second client presents the *same valid token* from a different device and network. "
    "Conventional validation accepts it (the token is genuine); SessionGuard sees two interleaving contexts, the risk "
    "climbs and the session is contained.",
    ["laptop", "replayer"],
    [LOGIN(), *_normal_browse(),
     Step("Harness copies the demo token", "note", advance_s=2,
          explanation="The lab harness hands the demo session's cookie to a second in-process client. This models an "
                      "attacker who has obtained a valid token (e.g. via malware or an XSS exfiltration) WITHOUT "
                      "reading any real browser's cookies.", expect="token copied to Client B"),
     Step("Client B replays the token", "replay_adopt", client="replayer", source_client="laptop",
          path="/api/portal/dashboard", advance_s=2, malicious=True,
          explanation="Client B sends the stolen token from a hosting network in another region with a different browser. "
                      "Conventional check: the token is valid -> ACCEPT. SessionGuard: new device + new region on an "
                      "active token.", expect="conventional: accept · SessionGuard: risk rises"),
     Step("Victim keeps working (interleaving)", "get", client="laptop", path="/api/portal/documents", advance_s=4,
          explanation="The legitimate client is still active. The token now alternates between two contexts within minutes "
                      "- the signature of replay.", expect="concurrency evidence appears"),
     Step("Client B probes documents", "get", client="replayer", path="/api/portal/documents", advance_s=3, malicious=True,
          explanation="More requests from Client B push distinct-contexts and context-switch features up; the ML model's "
                      "anomaly probability rises.", expect="risk approaches High/Critical"),
     Step("Client B attempts data export", "post", client="replayer", path="/api/portal/export", advance_s=3, malicious=True,
          explanation="A sensitive action from the suspicious context. Depending on where risk sits this is challenged "
                      "(step-up) or the session is revoked outright.", expect="403 step-up or 401 revoked"),
     Step("Client B retries after containment", "retry_revoked", client="replayer", path="/api/portal/dashboard",
          advance_s=3, malicious=True,
          explanation="The decisive check: the same valid token is replayed again after containment.",
          expect="401 · token rejected server-side")],
    teaches="Why a valid bearer token is not enough, and how contextual evidence + containment closes the gap."))

_add(Scenario(
    "device_anomaly", "Device Profile Anomaly", "Same token, a very different device fingerprint", "Smartphone", "device",
    "medium", ["RQ1", "RQ4"],
    "A request arrives on the session with a sharply different device profile (OS, browser family, device type). "
    "The detector raises risk but - crucially - a device change alone is treated as suspicion, not proof.",
    ["laptop", "home_other_device"],
    [LOGIN(), *_normal_browse(),
     Step("Request from a foreign device", "replay_adopt", client="home_other_device", source_client="laptop",
          path="/api/portal/dashboard", advance_s=4, malicious=True,
          explanation="Firefox on Linux appears on a session baselined to Chrome on Windows - but from the victim's own "
                      "home network, so ONLY the device signal fires (the network still matches the baseline).",
          expect="DEVICE_PROFILE_CHANGED · risk Elevated/High"),
     Step("Same device reads documents", "get", client="home_other_device", path="/api/portal/documents", advance_s=18,
          malicious=True,
          explanation="The device inconsistency persists but, with no network change and human-paced requests, risk stays "
                      "below Critical - the policy avoids over-reacting to a device change by itself.",
          expect="risk holds, not auto-revoked")],
    teaches="Proportionality: a single changed signal raises risk without forcing revocation."))

_add(Scenario(
    "network_anomaly", "Network Context Anomaly", "Impossible-travel style region change", "Globe", "network", "medium",
    ["RQ1", "RQ4"],
    "The same session suddenly originates from a different fictional region (RFC 5737 documentation ranges mapped to "
    "fictional regions - no real IPs). Combined with other evidence this is a strong signal.",
    ["laptop", "replayer_cloned"],
    [LOGIN(), *_normal_browse(),
     Step("Session jumps region", "replay_adopt", client="replayer_cloned", source_client="laptop",
          path="/api/portal/dashboard", advance_s=4, malicious=True,
          explanation="The attacker clones the victim's User-Agent (so device looks identical) but connects from a "
                      "residential-proxy network in another region. Only the network signal fires.",
          expect="IP_CONTEXT_CHANGED · risk Elevated"),
     Step("Continues from the new region", "get", client="replayer_cloned", path="/api/portal/documents", advance_s=5,
          malicious=True,
          explanation="Shows that a cloned UA defeats the device signal, which is exactly why multiple weak signals are "
                      "fused rather than trusted individually.", expect="network evidence sustained")],
    teaches="Why metadata alone is insufficient and signal fusion matters."))

_add(Scenario(
    "request_burst", "Abnormal Request Behaviour", "Scripted bursts and privilege probing", "Activity", "behavior", "high",
    ["RQ1", "RQ2"],
    "An automated client hammers endpoints, probes an admin route and triggers authorization failures. Behavioural "
    "features (rate, authz failures, admin probing, automation UA) drive the score up.",
    ["laptop", "script"],
    [LOGIN(), Step("Load dashboard", "get", path="/api/portal/dashboard", advance_s=3, expect="200 · Low",
                   explanation="A single normal request to establish the baseline."),
     Step("Scripted burst (12 requests)", "get", client="script", source_client="laptop", path="/api/portal/documents",
          advance_s=0.4, repeat=12, malicious=True,
          explanation="An automation tool, using the owner's own token, issues a rapid burst. rate_10s / rate_60s spike "
                      "and automation_ua fires.", expect="ANOMALOUS_BEHAVIOR · risk climbs"),
     Step("Probe admin endpoint", "get", client="script", path="/api/security/overview", advance_s=0.5, repeat=3,
          malicious=True, explanation="The script, authenticated as a normal user, repeatedly probes an admin-only route. "
                                       "Each attempt is denied (403) and counts as an authz failure + admin probe.",
          expect="403 each · admin_probe + authz_failures rise"),
     Step("Attempt sensitive export", "post", client="script", path="/api/portal/export", advance_s=0.5, malicious=True,
          explanation="With behaviour already anomalous, the sensitive action tips the session into containment.",
          expect="step-up or revoke")],
    teaches="How purely behavioural evidence (no device/network change) is detected."))

_add(Scenario(
    "revocation", "Automated Containment", "Drive to Critical, then prove the token is dead", "Ban", "containment", "critical",
    ["RQ3"],
    "Focuses on Stage 4. The session is pushed to Critical risk and the containment engine revokes it server-side; the "
    "same token is then retried to prove revocation is enforced on the backend, not hidden in the UI.",
    ["laptop", "replayer", "script"],
    [LOGIN(), *_normal_browse(),
     Step("Replay from foreign context", "replay_adopt", client="replayer", source_client="laptop",
          path="/api/portal/dashboard", advance_s=3, malicious=True,
          explanation="Device + network both change on the live token.", expect="risk High"),
     Step("Burst to push past Critical", "get", client="replayer", path="/api/portal/documents", advance_s=0.5, repeat=6,
          malicious=True, explanation="Concurrency + behaviour evidence fuse and the score crosses the Critical threshold.",
          expect="risk Critical"),
     Step("Containment fires", "post", client="replayer", path="/api/portal/export", advance_s=2, malicious=True,
          explanation="At Critical the policy revokes the session. SESSION_REVOKED + THREAT_CONTAINED are logged with the "
                      "containment latency.", expect="401 · SESSION_REVOKED"),
     Step("Retry the revoked token", "retry_revoked", client="replayer", path="/api/portal/dashboard", advance_s=2,
          malicious=True, explanation="The revoked token is presented again from the attacker context.",
          expect="401 · rejected"),
     Step("Legitimate client is also blocked", "retry_revoked", client="laptop", path="/api/portal/dashboard", advance_s=2,
          explanation="Because the server-side session is gone, even the original client must re-authenticate. This is the "
                      "deliberate cost of containment - the token, not the person, is what was compromised.",
          expect="401 · must sign in again")],
    teaches="Server-side revocation and measurable containment latency."))

_add(Scenario(
    "false_positive", "False Positive & Recovery", "A legitimate user travels and recovers via step-up", "UserCheck",
    "recovery", "low", ["RQ4"],
    "The honesty scenario. A genuine user changes network and device (travel + browser update). Risk rises and a "
    "sensitive action is challenged - but a correct password step-up re-baselines trust and clears the score, with no "
    "permanent lockout.",
    ["laptop", "cafe", "phone"],
    [LOGIN(), *_normal_browse(),
     Step("User moves to café Wi-Fi", "get", client="cafe", source_client="laptop", path="/api/portal/dashboard",
          advance_s=180,
          explanation="A few minutes later the same laptop (same browser, same token) is on café Wi-Fi - same region, new "
                      "network block. A mild network signal appears.", expect="risk Elevated"),
     Step("Later, switches to phone", "get", client="phone", source_client="laptop", path="/api/portal/dashboard",
          advance_s=240, malicious=False,
          explanation="An hour later the user is on their phone (new device + mobile network). Risk rises further - this "
                      "looks a lot like the replay scenario, which is the point.", expect="risk High"),
     Step("Sensitive action is challenged", "post", client="phone", path="/api/portal/export", advance_s=5,
          explanation="The sensitive export is not silently blocked; the user is asked to confirm their password (step-up). "
                      "This is a password re-check, NOT multi-factor authentication.", expect="403 · step_up_required"),
     Step("User passes the password challenge", "reauth", client="phone", advance_s=8, password="use-default",
          explanation="A correct password rotates the token, re-baselines device + network to the phone and resets risk "
                      "to 0 - recovery without locking the account.", expect="200 · token rotated · risk 0"),
     Step("Sensitive action now succeeds", "post", client="phone", path="/api/portal/export", advance_s=4,
          explanation="With trust re-established, the same action is allowed.", expect="200 · allowed")],
    teaches="The false-positive/usability trade-off and graceful recovery."))

_add(Scenario(
    "bitm", "Synthetic BITM Indicators", "Simulated Browser-in-the-Middle relay telemetry", "Network", "relay", "high",
    ["RQ1", "RQ2"],
    "A telemetry SIMULATION (clearly labelled) of indicators associated with Browser-in-the-Middle relay behaviour: "
    "abnormal OIDC token-exchange latency and a relay indicator. No real reverse-proxy or phishing infrastructure is "
    "built; these are injected signals only.",
    ["laptop", "relay"],
    [LOGIN(), *_normal_browse(),
     Step("Relay forwards a request", "replay_adopt", client="relay", source_client="laptop", path="/api/portal/dashboard",
          advance_s=3, malicious=True,
          synthetic={"token_exchange_ms": 920, "relay_indicator": 0.82, "cookie_misuse": 1},
          explanation="The relay forwards the victim's real token and User-Agent (so device looks legitimate) but the "
                      "harness injects synthetic relay timing: a 920 ms token exchange and a high relay indicator.",
          expect="BITM_RELAY_SUSPECTED (synthetic) · risk High"),
     Step("Second relayed request", "get", client="relay", path="/api/portal/documents", advance_s=4, malicious=True,
          synthetic={"token_exchange_ms": 870, "relay_indicator": 0.78, "cookie_misuse": 1},
          explanation="Sustained synthetic relay indicators keep risk elevated. Every resulting event is tagged "
                      "synthetic=true so it is never mistaken for a real browser observation.",
          expect="risk sustained High")],
    teaches="How optional synthetic signals extend detection, kept honest with explicit labelling."))


def scenario_catalog() -> list[dict[str, Any]]:
    return [{
        "key": s.key, "name": s.name, "tagline": s.tagline, "icon": s.icon, "category": s.category,
        "threat_level": s.threat_level, "rq": s.rq, "summary": s.summary, "teaches": s.teaches,
        "clients": s.clients, "step_count": len(s.steps),
        "steps": [{"index": i, "title": st.title, "action": st.action, "client": st.client, "path": st.path,
                   "explanation": st.explanation, "expect": st.expect, "malicious": st.malicious,
                   "synthetic": st.synthetic is not None, "repeat": st.repeat} for i, st in enumerate(s.steps)],
    } for s in SCENARIOS.values()]
