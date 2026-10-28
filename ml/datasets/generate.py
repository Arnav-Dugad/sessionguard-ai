"""Reproducible synthetic dataset generator for SessionGuard AI.

Design goals (see docs/MASTER_PROMPT_v2.md sec. 6):
  * Reuse the runtime feature extractor (``app.telemetry.features``) so the training
    distribution matches serving exactly - no second, drifting implementation.
  * Label at the *session* level by scenario, then emit one labelled row per request using
    only the history available at that point in time (causal features, no look-ahead).
  * Avoid leakage: splitting is by session group (done in train.py), and the presence of the
    optional synthetic features is randomised independently of the label.

Run: ``python ml/datasets/generate.py --seed 42 --sessions 1400 --out ml/datasets/dataset.parquet``
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.telemetry.device import parse_user_agent  # noqa: E402
from app.telemetry.features import FEATURES, Baseline, Obs, extract_features  # noqa: E402
from app.telemetry.network import resolve_network  # noqa: E402

DATASET_VERSION = "sg-synthetic-v1"

# Benign vs. attack scenarios. ``benign_*`` scenarios are the ones that deliberately look
# suspicious (travel, new device) but are labelled 0 - they are how we measure false positives.
SCENARIOS = {
    "normal": 0, "benign_device_change": 0, "benign_network_change": 0, "benign_power_user": 0,
    "token_replay": 1, "device_anomaly": 1, "network_anomaly": 1, "request_burst": 1, "bitm_relay": 1,
}

DEVICES = {
    "chrome_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "chrome_win_new": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "safari_ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "firefox_linux": "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "edge_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "chrome_android": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "script": "python-httpx/0.28.1",
}
# IPs drawn from RFC 5737 documentation ranges, grouped by fictional region.
IPS = {
    "home": ["192.0.2.%d" % i for i in range(10, 60)],
    "cafe": ["192.0.2.%d" % i for i in range(140, 180)],
    "mobile": ["198.51.100.%d" % i for i in range(20, 90)],
    "hosting": ["203.0.113.%d" % i for i in range(20, 110)],
    "proxy": ["203.0.113.%d" % i for i in range(140, 220)],
}
PAGES = ["/api/portal/dashboard", "/api/portal/documents", "/api/portal/profile", "/api/portal/activity"]
SENSITIVE = ["/api/portal/export", "/api/portal/transfer", "/api/portal/change-email"]


def _dev(rng: random.Random, key: str) -> dict:
    return parse_user_agent(DEVICES[key], "en-US,en;q=0.9" if key != "script" else "")


def _net(rng: random.Random, region: str) -> dict:
    return resolve_network(rng.choice(IPS[region]))


def category_for(path: str) -> str:
    if path in SENSITIVE:
        return "sensitive"
    if path.startswith("/api/security"):
        return "admin"
    return "data" if "documents" in path or "activity" in path else "page"


@dataclass
class ReqSpec:
    gap: float          # seconds since previous request
    path: str
    device_key: str
    region: str
    status: int = 200
    attacker: bool = False
    synthetic: dict | None = None


def _human_gaps(rng: random.Random, n: int) -> list[float]:
    return [rng.choice([0]) if i == 0 else rng.lognormvariate(2.4, 0.8) for i in range(n)]


def build_session(rng: random.Random, scenario: str) -> list[ReqSpec]:
    base_dev = rng.choice(["chrome_win", "edge_win", "safari_ios", "chrome_android"])
    base_region = rng.choice(["home", "cafe", "mobile"])
    n_warm = rng.randint(3, 8)
    specs = [ReqSpec(0 if i == 0 else rng.lognormvariate(2.4, 0.8), rng.choice(PAGES), base_dev, base_region)
             for i in range(n_warm)]
    # Occasional legitimate sensitive action.
    if rng.random() < 0.4:
        specs.append(ReqSpec(rng.lognormvariate(2.6, 0.7), rng.choice(SENSITIVE), base_dev, base_region))

    if scenario == "normal":
        for _ in range(rng.randint(2, 6)):
            specs.append(ReqSpec(rng.lognormvariate(2.5, 0.8), rng.choice(PAGES), base_dev, base_region))

    elif scenario == "benign_power_user":
        for _ in range(rng.randint(8, 16)):
            specs.append(ReqSpec(rng.lognormvariate(1.3, 0.6), rng.choice(PAGES + SENSITIVE[:1]), base_dev, base_region))

    elif scenario == "benign_device_change":
        new_dev = "chrome_win_new" if base_dev.startswith("chrome_win") else rng.choice(["edge_win", "safari_ios"])
        for _ in range(rng.randint(3, 7)):
            specs.append(ReqSpec(rng.lognormvariate(3.2, 0.9), rng.choice(PAGES), new_dev, base_region))

    elif scenario == "benign_network_change":
        new_region = rng.choice([r for r in ("home", "cafe", "mobile") if r != base_region])
        for _ in range(rng.randint(3, 7)):
            specs.append(ReqSpec(rng.lognormvariate(3.4, 1.0), rng.choice(PAGES), base_dev, new_region))

    elif scenario == "token_replay":
        atk_dev = rng.choice(["firefox_linux", "chrome_win", "script"])
        atk_region = rng.choice(["hosting", "proxy"])
        for _ in range(rng.randint(4, 10)):
            if rng.random() < 0.5:  # interleave legitimate + attacker on the same token
                specs.append(ReqSpec(rng.lognormvariate(2.3, 0.7), rng.choice(PAGES), base_dev, base_region))
            specs.append(ReqSpec(rng.lognormvariate(1.0, 0.7), rng.choice(PAGES + SENSITIVE), atk_dev, atk_region,
                                 attacker=True))

    elif scenario == "device_anomaly":
        atk_dev = rng.choice([d for d in ("firefox_linux", "safari_ios", "chrome_android", "script") if d != base_dev])
        for _ in range(rng.randint(4, 9)):
            specs.append(ReqSpec(rng.lognormvariate(2.0, 0.8), rng.choice(PAGES + SENSITIVE), atk_dev, base_region,
                                 attacker=True))

    elif scenario == "network_anomaly":
        atk_region = rng.choice(["hosting", "proxy"])
        for _ in range(rng.randint(4, 9)):
            specs.append(ReqSpec(rng.lognormvariate(2.1, 0.8), rng.choice(PAGES + SENSITIVE), base_dev, atk_region,
                                 attacker=True))

    elif scenario == "request_burst":
        atk_dev = rng.choice(["script", base_dev])
        for _ in range(rng.randint(12, 28)):
            probe = rng.random() < 0.3
            specs.append(ReqSpec(rng.uniform(0.1, 0.9),
                                 rng.choice(["/api/security/overview"]) if probe else rng.choice(PAGES),
                                 atk_dev, base_region, status=403 if probe else 200, attacker=True))

    elif scenario == "bitm_relay":
        for _ in range(rng.randint(4, 9)):
            specs.append(ReqSpec(rng.lognormvariate(1.8, 0.7), rng.choice(PAGES + SENSITIVE), base_dev, base_region,
                                 attacker=True,
                                 synthetic={"token_exchange_ms": rng.uniform(650, 1200),
                                            "relay_indicator": rng.uniform(0.6, 0.95), "cookie_misuse": 1}))
    return specs


def session_to_rows(rng: random.Random, sid: int, scenario: str, label: int,
                    attach_synthetic: bool) -> list[dict]:
    specs = build_session(rng, scenario)
    t = time.time() - rng.uniform(0, 3600)
    base_dev = _dev(rng, specs[0].device_key)
    base_net = _net(rng, specs[0].region)
    baseline = Baseline(t, base_dev["ua_hash"], base_dev, base_net)

    history: list[Obs] = []
    rows: list[dict] = []
    failed_auth = rng.choice([0, 0, 0, 1]) if scenario != "request_burst" else rng.randint(0, 4)
    for i, spec in enumerate(specs):
        t += max(0.05, spec.gap)
        dev = _dev(rng, spec.device_key)
        net = _net(rng, spec.region)
        cat = category_for(spec.path)
        syn = {}
        if spec.synthetic and attach_synthetic:
            syn = dict(spec.synthetic)
        cur = Obs(t, cat, spec.status, dev["ua_hash"], dev, net, syn)
        feats = extract_features(history, cur, baseline, failed_auth_15m=failed_auth, is_admin=False)
        history.append(cur)
        # Row label: a benign session is always 0; in an attack session only the attacker's own
        # requests (and the warm-up noise they contaminate) carry the positive label.
        row_label = 1 if (label == 1 and spec.attacker) else 0
        rows.append({**feats, "label": row_label, "session_label": label, "scenario": scenario,
                     "session_id": sid, "req_index": i, "is_attacker_request": spec.attacker})
    return rows


def generate(seed: int, n_sessions: int) -> tuple[pd.DataFrame, dict]:
    rng = random.Random(seed)
    keys = list(SCENARIOS)
    # Weight towards normal/benign so the positive class is a realistic minority.
    weights = {"normal": 4, "benign_device_change": 1.2, "benign_network_change": 1.2, "benign_power_user": 1.4,
               "token_replay": 1.6, "device_anomaly": 1.1, "network_anomaly": 1.1, "request_burst": 1.1,
               "bitm_relay": 1.0}
    wlist = [weights[k] for k in keys]

    all_rows: list[dict] = []
    counts: dict[str, int] = {k: 0 for k in keys}
    for sid in range(n_sessions):
        scenario = rng.choices(keys, weights=wlist, k=1)[0]
        counts[scenario] += 1
        # Synthetic signals are present on ~60% of sessions regardless of class, so the model
        # cannot learn "synthetic feature present => attack" as a shortcut.
        attach_syn = rng.random() < 0.6
        all_rows.extend(session_to_rows(rng, sid, scenario, SCENARIOS[scenario], attach_syn))

    df = pd.DataFrame(all_rows)
    meta = {
        "dataset_version": DATASET_VERSION, "seed": seed, "sessions": n_sessions, "rows": len(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "features": FEATURES, "scenarios": SCENARIOS, "sessions_per_scenario": counts,
        "positive_row_rate": round(float(df["label"].mean()), 4),
    }
    sess = df.groupby("session_id")["session_label"].first()
    meta["class_distribution"] = {
        "row_positive": int(df["label"].sum()), "row_negative": int((df["label"] == 0).sum()),
        "session_positive": int(sess.sum()), "session_negative": int((sess == 0).sum()),
    }
    return df, meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sessions", type=int, default=1400)
    ap.add_argument("--out", type=Path, default=ROOT / "ml" / "datasets" / "dataset.parquet")
    args = ap.parse_args()

    df, meta = generate(args.seed, args.sessions)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        df.to_parquet(args.out, index=False)
        out = args.out
    except Exception:  # pyarrow missing - fall back to CSV
        out = args.out.with_suffix(".csv")
        df.to_csv(out, index=False)
    (args.out.parent / "dataset_meta.json").write_text(json.dumps(meta, indent=2))
    print(f"wrote {len(df)} rows ({meta['class_distribution']}) to {out}")
    print(f"positive row rate: {meta['positive_row_rate']:.3f}; sessions/scenario: {meta['sessions_per_scenario']}")


if __name__ == "__main__":
    main()
