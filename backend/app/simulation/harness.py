"""In-process test clients for the Attack Simulation Lab.

Every lab client is an ``httpx.AsyncClient`` bound to *this* FastAPI app through
``ASGITransport`` - requests travel through the complete middleware / routing / pipeline
stack, but no network socket is opened and no other host can be addressed. The simulated
client address is set at the transport layer (the server sees it as the TCP peer), so the
lab never relies on spoofable headers such as X-Forwarded-For.

Only the seeded fictional demo accounts can be used by the lab (see ``runner.LAB_USERS``).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_settings
from app.telemetry.context import CLIENT_HEADER, CLOCK_HEADER, HARNESS_HEADER, HARNESS_SECRET, RUN_HEADER, SYNTHETIC_HEADER

LAB_HOST = "helios-vault.lab"


@dataclass(frozen=True)
class ClientProfile:
    key: str
    label: str
    role: str  # legitimate | adversary
    ip: str
    user_agent: str
    accept_language: str
    description: str


UA_CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
UA_CHROME_WIN_NEW = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
UA_SAFARI_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                 "Version/18.1 Mobile/15E148 Safari/604.1")
UA_FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
UA_SCRIPT = "python-httpx/0.28.1"

PROFILES: dict[str, ClientProfile] = {p.key: p for p in [
    ClientProfile("laptop", "Legitimate user · Laptop", "legitimate", "192.0.2.24", UA_CHROME_WIN, "en-US,en;q=0.9",
                  "Chrome on Windows, home fibre in Northbridge (the trusted baseline)"),
    ClientProfile("laptop_updated", "Legitimate user · Laptop (browser updated)", "legitimate", "192.0.2.24", UA_CHROME_WIN_NEW,
                  "en-US,en;q=0.9", "Same laptop after a browser update"),
    ClientProfile("cafe", "Legitimate user · Café Wi-Fi", "legitimate", "192.0.2.150", UA_CHROME_WIN, "en-US,en;q=0.9",
                  "Same laptop on public Wi-Fi in the same region"),
    ClientProfile("phone", "Legitimate user · Phone", "legitimate", "198.51.100.37", UA_SAFARI_IOS, "en-US,en;q=0.9",
                  "Safari on iPhone over the mobile network (same region)"),
    ClientProfile("home_other_device", "Adversary · Foreign device, same network", "adversary", "192.0.2.41",
                  UA_FIREFOX_LINUX, "en-GB,en;q=0.8",
                  "Firefox on Linux from the victim's own home network - isolates the device signal from the network signal"),
    ClientProfile("replayer", "Adversary · Replayed token", "adversary", "203.0.113.66", UA_FIREFOX_LINUX, "en-GB,en;q=0.8",
                  "Second client presenting the copied demo token from a hosting network in another region"),
    ClientProfile("replayer_cloned", "Adversary · Replayed token, cloned UA", "adversary", "203.0.113.200", UA_CHROME_WIN,
                  "en-US,en;q=0.9", "Copies the victim's User-Agent and uses a residential proxy - harder to spot"),
    ClientProfile("script", "Adversary · Automated script", "adversary", "203.0.113.70", UA_SCRIPT, "",
                  "Scripted HTTP client hammering endpoints"),
    ClientProfile("relay", "Relay · BITM telemetry (synthetic)", "adversary", "203.0.113.90", UA_CHROME_WIN, "en-US,en;q=0.9",
                  "Synthetic relay: forwards the victim's real UA, adds token-exchange latency indicators"),
]}


@dataclass
class Exchange:
    """One request/response pair, sanitised for display (no token values)."""

    client: str
    client_label: str
    role: str
    malicious: bool
    method: str
    path: str
    status: int
    ok: bool
    response: Any
    risk: float | None
    band: str | None
    decision: str | None
    request_log_id: int | None
    virtual_ts: float
    latency_ms: float
    request_headers: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class LabClient:
    def __init__(self, app, profile: ClientProfile, run_id: int):
        self.profile = profile
        self.run_id = run_id
        transport = httpx.ASGITransport(app=app, client=(profile.ip, 50000))
        self.http = httpx.AsyncClient(transport=transport, base_url=f"http://{LAB_HOST}", timeout=30)

    async def close(self) -> None:
        await self.http.aclose()

    @property
    def session_token(self) -> str | None:
        return self.http.cookies.get(get_settings().session_cookie_name)

    @property
    def csrf_token(self) -> str | None:
        return self.http.cookies.get(get_settings().csrf_cookie_name)

    def adopt_cookies_from(self, other: "LabClient") -> None:
        """Lab-only: give this client the same demo-session cookies the other client was issued."""
        s = get_settings()
        for name in (s.session_cookie_name, s.csrf_cookie_name):
            value = other.http.cookies.get(name)
            if value:
                self.http.cookies.set(name, value, domain=LAB_HOST, path="/")

    def _headers(self, clock: float, synthetic: dict[str, float] | None) -> dict[str, str]:
        h = {
            "User-Agent": self.profile.user_agent,
            "Accept-Language": self.profile.accept_language,
            HARNESS_HEADER: HARNESS_SECRET,
            CLOCK_HEADER: f"{clock:.3f}",
            CLIENT_HEADER: self.profile.key,
            RUN_HEADER: str(self.run_id),
        }
        if synthetic:
            h[SYNTHETIC_HEADER] = json.dumps(synthetic)
        csrf = self.csrf_token
        if csrf:
            h[get_settings().csrf_header_name] = csrf
        return h

    async def request(self, method: str, path: str, *, clock: float, json_body: Any = None,
                      synthetic: dict[str, float] | None = None, malicious: bool = False, note: str = "") -> Exchange:
        headers = self._headers(clock, synthetic)
        t0 = time.perf_counter()
        r = await self.http.request(method, path, json=json_body, headers=headers)
        latency = (time.perf_counter() - t0) * 1000
        try:
            body = r.json()
        except ValueError:
            body = r.text[:500]
        if isinstance(body, dict) and "csrf_token" in body:
            body = {**body, "csrf_token": "•••• (hidden)"}
        shown = {k: v for k, v in headers.items() if not k.startswith("X-SG-") and k != get_settings().csrf_header_name}
        shown["Cookie"] = "sg_session=•••• (token hidden)" if self.session_token else "(none)"
        if synthetic:
            shown["Synthetic telemetry"] = json.dumps(synthetic)
        return Exchange(
            client=self.profile.key, client_label=self.profile.label, role=self.profile.role, malicious=malicious,
            method=method, path=path, status=r.status_code, ok=r.is_success, response=body,
            risk=float(r.headers["X-SG-Risk"]) if "X-SG-Risk" in r.headers else None,
            band=r.headers.get("X-SG-Band"), decision=r.headers.get("X-SG-Decision"),
            request_log_id=int(r.headers["X-SG-Request-Log"]) if "X-SG-Request-Log" in r.headers else None,
            virtual_ts=clock, latency_ms=round(latency, 2), request_headers=shown, note=note,
        )
