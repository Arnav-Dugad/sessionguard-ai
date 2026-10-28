"""Server-side User-Agent parsing.

Everything here is derived from request headers, which the client fully controls.
It is useful *corroborating* evidence, never proof - see docs/ARCHITECTURE.md#trust.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

_AUTOMATION = re.compile(
    r"(curl/|wget/|python-requests|python-httpx|aiohttp|go-http-client|okhttp|postmanruntime|"
    r"headlesschrome|phantomjs|selenium|puppeteer|playwright|scrapy|httpie|java/|libwww)",
    re.I,
)

_BROWSERS: list[tuple[str, re.Pattern[str]]] = [
    ("Edge", re.compile(r"Edg(?:e|A|iOS)?/(\d+)")),
    ("Opera", re.compile(r"OPR/(\d+)")),
    ("Samsung Internet", re.compile(r"SamsungBrowser/(\d+)")),
    ("Firefox", re.compile(r"(?:Firefox|FxiOS)/(\d+)")),
    ("Chrome", re.compile(r"(?:HeadlessChrome|Chrome|CriOS)/(\d+)")),
    ("Safari", re.compile(r"Version/(\d+).*Safari/")),
]

_OS: list[tuple[str, re.Pattern[str]]] = [
    ("iOS", re.compile(r"iPhone|iPad|iPod")),
    ("Android", re.compile(r"Android")),
    ("Windows", re.compile(r"Windows NT")),
    ("macOS", re.compile(r"Mac OS X|Macintosh")),
    ("ChromeOS", re.compile(r"CrOS")),
    ("Linux", re.compile(r"Linux|X11")),
]


def ua_hash(user_agent: str) -> str:
    return hashlib.sha256(user_agent.encode()).hexdigest()[:16]


def parse_user_agent(user_agent: str | None, accept_language: str | None = None) -> dict[str, Any]:
    ua = (user_agent or "").strip()
    automation = bool(_AUTOMATION.search(ua)) or ua == ""

    browser, major = "Unknown", ""
    for name, pattern in _BROWSERS:
        m = pattern.search(ua)
        if m:
            browser, major = name, m.group(1)
            break
    if automation:
        tool = _AUTOMATION.search(ua)
        browser = (tool.group(1).rstrip("/") if tool else "empty-ua").lower()

    os_name = next((name for name, p in _OS if p.search(ua)), "Unknown")

    if automation:
        device_type = "bot"
    elif "iPad" in ua or "Tablet" in ua:
        device_type = "tablet"
    elif re.search(r"Mobile|iPhone|Android", ua):
        device_type = "mobile"
    else:
        device_type = "desktop"

    lang = (accept_language or "").split(",")[0].split(";")[0].strip().lower() or "none"

    label_browser = f"{browser} {major}".strip()
    return {
        "browser": browser,
        "browser_major": major,
        "os": os_name,
        "device_type": device_type,
        "lang": lang,
        "automation": automation,
        "ua_hash": ua_hash(ua),
        "label": f"{label_browser} · {os_name} · {device_type}",
    }
