"""Per-request observation context.

The simulation harness runs *inside* the server process and authenticates itself with a
random per-process secret that never leaves memory. Only requests carrying that secret may
use the virtual clock or inject synthetic telemetry. Browser requests cannot forge it.
"""
from __future__ import annotations

import json
import math
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from .device import parse_user_agent
from .network import resolve_network

HARNESS_SECRET = secrets.token_hex(32)
HARNESS_HEADER = "X-SG-Harness"
CLOCK_HEADER = "X-SG-Sim-Clock"
CLIENT_HEADER = "X-SG-Client"
SYNTHETIC_HEADER = "X-SG-Synthetic"
RUN_HEADER = "X-SG-Run"

SYNTHETIC_KEYS = ("token_exchange_ms", "relay_indicator", "cookie_misuse")


@dataclass
class RequestContext:
    ts: float
    now: datetime
    is_harness: bool
    client_label: str | None
    ip: str
    device: dict[str, Any]
    network: dict[str, Any]
    synthetic: dict[str, float] = field(default_factory=dict)
    run_id: int | None = None


def is_harness_request(request: Request) -> bool:
    supplied = request.headers.get(HARNESS_HEADER, "")
    return bool(supplied) and secrets.compare_digest(supplied, HARNESS_SECRET)


def build_context(request: Request) -> RequestContext:
    harness = is_harness_request(request)
    ts = time.time()
    synthetic: dict[str, float] = {}
    label = None
    run_id = None
    if harness:
        run_raw = request.headers.get(RUN_HEADER, "")
        run_id = int(run_raw) if run_raw.isdigit() else None
        try:
            ts = float(request.headers.get(CLOCK_HEADER, ts))
        except ValueError:
            pass
        label = request.headers.get(CLIENT_HEADER)
        raw = request.headers.get(SYNTHETIC_HEADER)
        if raw:
            try:
                parsed = json.loads(raw)
                synthetic = {
                    k: float(parsed[k]) for k in SYNTHETIC_KEYS if k in parsed and math.isfinite(float(parsed[k]))
                }
            except (ValueError, TypeError):
                synthetic = {}

    # The TCP peer address. X-Forwarded-For is deliberately ignored: it is client-controlled.
    ip = request.client.host if request.client else "0.0.0.0"
    device = parse_user_agent(request.headers.get("user-agent"), request.headers.get("accept-language"))
    return RequestContext(
        ts=ts,
        now=datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None),
        is_harness=harness,
        client_label=label,
        ip=ip,
        device=device,
        network=resolve_network(ip),
        synthetic=synthetic,
        run_id=run_id,
    )
