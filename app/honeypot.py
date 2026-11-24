#!/usr/bin/env python3
"""
Medium-Interaction Blog + IoT Portal Honeypot (Standard Library Only).

Simulates a multi-layer decoy portal combining:
- Blog & public discovery routes (/, /blog, /feed.xml, /rss.xml, /sitemap.xml,
  /robots.txt, /category/tech, /category/iot, /articles/101)
- Auth & account routes (/login, /logout, /register, /signup, /password/reset,
  /boaform/admin/formLogin, /wp-login.php)
- Content & admin routes (/posts/new, /posts/list, /admin, /admin/dashboard,
  /admin/posts)
- IoT gateway management routes (/iot/admin, /iot/status, /iot/network,
  /iot/wifi, /iot/firmware, /cgi-bin/luci)
- API, config & recon decoy routes (/api/v1/status, /api/v1/posts,
  /api/v1/auth/login, /api/v1/device/status, /api/v1/device/config, /.env,
  /config.json, /backup.zip, /server-status, /actuator, /actuator/env)

All state stays in memory and structured JSON events are emitted to stdout.
No real files are written, no external network calls are made, and no OS
commands or dynamic code evaluation (subprocess / os.system / eval) are used.
"""

from __future__ import annotations

import base64
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


_PROXY_INTERNAL_HEADERS: frozenset[str] = frozenset(
    {
        "x-real-ip",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-proxy-verified",
    }
)

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")

_ATTACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sqli_pattern", re.compile(r"(?:\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|--\s|/\*.*\*/)", re.IGNORECASE)),
    ("xss_pattern", re.compile(r"(?:<script\b|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE)),
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)),
    ("cmd_injection_terms", re.compile(r"(?:\bwget\b|\bcurl\b|\bchmod\b|\b/bin/sh\b|\b/bin/bash\b|;\s*id\b)", re.IGNORECASE)),
]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def sha256_short(value: str, length: int = 16) -> str:
    """Return a truncated SHA-256 digest for safe correlation."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def _classify_ip(ip_str: str) -> tuple[bool, str]:
    """Classify IPv4/IPv6 address scope without external calls."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "invalid"
    if addr.is_loopback:
        return False, "loopback"
    if addr.is_private:
        return False, "private"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False, "reserved"
    if isinstance(addr, ipaddress.IPv4Address) and (
        addr in ipaddress.ip_network("192.0.2.0/24")
        or addr in ipaddress.ip_network("198.51.100.0/24")
        or addr in ipaddress.ip_network("203.0.113.0/24")
    ):
        return False, "documentation"
    return True, "public"


def _decode_base64_candidates(text: str) -> list[str]:
    """Safely attempt base64 decoding and keep printable strings."""
    out: list[str] = []
    for token in _B64_RE.findall(text)[:10]:
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            raw = base64.b64decode(padded, validate=False)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            printable = "".join(ch for ch in decoded if ch.isprintable() or ch in "\r\n\t")
            if len(printable) >= 4:
                out.append(printable[:200])
        except Exception:
            continue
    return out


class HttpFingerprinter:
    """Passive HTTP-layer communication fingerprinter excluding proxy headers."""

    def __init__(self) -> None:
        self._last_ts: dict[str, float] = {}
        self._fp_counts: defaultdict[str, int] = defaultdict(int)

    def fingerprint(
        self,
        client_ip: str,
        method: str,
        path: str,
        raw_headers: list[tuple[str, str]],
        arrival_monotonic: float,
    ) -> dict[str, Any]:
        """Compute an HTTP communication fingerprint from client-originated headers."""
        filtered_headers = [
            (k, v)
            for k, v in raw_headers
            if k.lower().strip() not in _PROXY_INTERNAL_HEADERS
        ]

        ordered_names = [k.lower().strip() for k, _ in filtered_headers]
        header_map: dict[str, str] = {}
        for k, v in filtered_headers:
            lk = k.lower().strip()
            if lk not in header_map:
                header_map[lk] = v.strip()

        ua = header_map.get("user-agent", "")
        accept = header_map.get("accept", "")
        enc = header_map.get("accept-encoding", "")
        lang = header_map.get("accept-language", "")

        basis = (
            f"order={'|'.join(ordered_names[:25])};"
            f"ua={int('user-agent' in header_map)};"
            f"acc={int('accept' in header_map)};"
            f"enc={int('accept-encoding' in header_map)};"
            f"lang={int('accept-language' in header_map)};"
            f"cookie={int('cookie' in header_map)};"
            f"ref={int('referer' in header_map)}"
        )
        fp_id = f"httpfp_{sha256_short(basis, 12)}"
        self._fp_counts[fp_id] += 1

        prev = self._last_ts.get(client_ip)
        interval_ms: float | None = None
        if prev is not None and arrival_monotonic >= prev:
            interval_ms = round((arrival_monotonic - prev) * 1000.0, 2)
        self._last_ts[client_ip] = arrival_monotonic

        signals: list[str] = []
        if not ua:
            signals.append("missing_user_agent")
        if "accept-language" not in header_map:
            signals.append("missing_accept_language")
        if "accept-encoding" not in header_map:
            signals.append("missing_accept_encoding")
        if ("mozilla/" in ua.lower() or "chrome/" in ua.lower()) and not any(
            h.startswith("sec-fetch-") for h in header_map
        ):
            signals.append("browser_ua_without_sec_fetch")
        if accept == "*/*" and len(ordered_names) <= 5:
            signals.append("minimal_script_headers")
        if interval_ms is not None and interval_ms < 50.0:
            signals.append("rapid_request_cadence")

        return {
            "fp_id": fp_id,
            "fp_seen_count": self._fp_counts[fp_id],
            "method": method,
            "path": path,
            "header_count": len(ordered_names),
            "header_order": ordered_names[:20],
            "ua_hash": sha256_short(ua, 10) if ua else "none",
            "accept_summary": accept[:80],
            "accept_encoding_summary": enc[:60],
            "accept_language_summary": lang[:60],
            "interval_ms_from_prev": interval_ms,
            "signals": signals,
        }


class PayloadOsintEngine:
    """Extract payload IOC candidates and match against local in-memory OSINT sets."""

    def __init__(self) -> None:
        self.known_bad_ips: set[str] = {"198.51.100.66", "203.0.113.77"}
        self.known_bad_domains: set[str] = {
            "c2-sinkhole-decoy.example.invalid",
            "stage-dropper-decoy.example.invalid",
        }
        self.known_tools: list[str] = [
            "sqlmap",
            "nikto",
            "masscan",
            "zgrab",
            "nuclei",
            "dirbuster",
            "gobuster",
            "curl/",
            "python-requests",
        ]

    def analyze(
        self,
        client_ip: str,
        user_agent: str,
        raw_query: str,
        payload_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Extract C2 candidate indicators and correlate with local OSINT sets."""
        parts: list[str] = []
        if raw_query:
            parts.append(unquote(raw_query))
        for k, v in list(payload_dict.items())[:30]:
            parts.append(f"{k}={v}")
        raw_text = unquote("\n".join(parts))[:8000]

        decoded_b64 = _decode_base64_candidates(raw_text)
        corpus = raw_text + ("\n" + "\n".join(decoded_b64) if decoded_b64 else "")

        urls = list(dict.fromkeys(_URL_RE.findall(corpus)))[:20]
        raw_ips = list(dict.fromkeys(_IPV4_RE.findall(corpus)))[:20]
        domains = list(dict.fromkeys(d.lower() for d in _DOMAIN_RE.findall(corpus)))[:20]

        ip_items: list[dict[str, Any]] = []
        for ip_cand in raw_ips:
            is_pub, scope = _classify_ip(ip_cand)
            ip_items.append(
                {
                    "ip": ip_cand,
                    "scope": scope,
                    "is_public": is_pub,
                    "local_osint_match": ip_cand in self.known_bad_ips,
                }
            )

        matched_domains = [d for d in domains if d in self.known_bad_domains]
        matched_urls = [u for u in urls if any(bad in u.lower() for bad in self.known_bad_domains)]
        patterns = [tag for tag, rx in _ATTACK_PATTERNS if rx.search(corpus)]
        ua_hints = [t for t in self.known_tools if t in user_agent.lower()]

        client_pub, client_scope = _classify_ip(client_ip)
        osint_matches: list[dict[str, str]] = []
        if client_ip in self.known_bad_ips:
            osint_matches.append({"source": "local_ip_list", "indicator": client_ip, "kind": "client_ip"})
        for item in ip_items:
            if item["local_osint_match"]:
                osint_matches.append({"source": "local_ip_list", "indicator": item["ip"], "kind": "payload_ip"})
        for dom in matched_domains:
            osint_matches.append({"source": "local_domain_list", "indicator": dom, "kind": "payload_domain"})
        for u in matched_urls:
            osint_matches.append({"source": "local_domain_list", "indicator": u, "kind": "payload_url"})

        return {
            "client_ip_scope": client_scope,
            "client_ip_public": client_pub,
            "ua_tool_hints": ua_hints,
            "attack_patterns": patterns,
            "c2_candidates": {
                "urls": urls,
                "ips": ip_items,
                "domains": domains,
                "decoded_base64_count": len(decoded_b64),
            },
            "osint_correlation": {
                "mode": "local_in_memory_only",
                "match_count": len(osint_matches),
                "matches": osint_matches,
            },
        }


class BlogIoTPortalState:
    """Thread-safe in-memory state for Medium-Interaction Blog + IoT Portal."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started_at = utc_now_iso()
        self.events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.path_hits: Counter[str] = Counter()
        self.ip_hits: Counter[str] = Counter()
        self.failed_logins_by_ip: defaultdict[str, int] = defaultdict(int)
        self.fingerprinter = HttpFingerprinter()
        self.osint_engine = PayloadOsintEngine()

        self.users: dict[str, dict[str, str]] = {
            "admin": {"password_hash": sha256_short("PortalAdmin#2026"), "role": "admin"},
            "editor": {"password_hash": sha256_short("BlogEditor!2026"), "role": "editor"},
            "iot_ops": {"password_hash": sha256_short("IoTGateway@2026"), "role": "iot_admin"},
        }
        self.sessions: dict[str, dict[str, Any]] = {}

        self.articles: list[dict[str, Any]] = [
            {
                "id": 101,
                "title": "Hardening Edge Gateways and Observing Automated Web Scans",
                "category": "iot",
                "author": "iot_ops",
                "published_at": "2026-11-23 20:00 UTC",
                "summary": "Notes on separating management planes, firmware hygiene, and HTTP request telemetry.",
                "body": (
                    "Edge devices and web portals routinely face automated probes across login forms, "
                    "API endpoints, and legacy paths. Isolating management interfaces and recording "
                    "structured request telemetry provides clear visibility without exposing real assets."
                ),
            },
            {
                "id": 102,
                "title": "Structured HTTP Fingerprinting for Web Traffic Triage",
                "category": "tech",
                "author": "editor",
                "published_at": "2026-11-23 18:30 UTC",
                "summary": "Comparing header ordering, timing cadence, and payload indicators in traffic logs.",
                "body": (
                    "Combining header structure, request cadence, and payload indicator extraction helps "
                    "analysts separate standard browser traffic from scripted reconnaissance and probe bursts."
                ),
            },
            {
                "id": 103,
                "title": "Segmenting Sensor Subnets and Admin Consoles in Lab Networks",
                "category": "iot",
                "author": "admin",
                "published_at": "2026-11-23 16:15 UTC",
                "summary": "Practical layout notes for VLAN isolation, DHCP scopes, and staged firmware channels.",
                "body": (
                    "Lab and facility networks benefit from clear segmentation between telemetry endpoints, "
                    "guest wireless networks, and administrative consoles."
                ),
            },
        ]
        self.next_article_id = 104

        self.device_config: dict[str, Any] = {
            "device_model": "DecoyGateway-X200",
            "firmware_version": "v3.8.2-sim",
            "hostname": "edge-gw-sim-01",
            "wan": {"mode": "dhcp", "ip_address": "198.51.100.10", "gateway": "198.51.100.1"},
            "lan": {"ip_address": "192.168.10.1", "subnet_mask": "255.255.255.0", "dhcp_enabled": True},
            "wifi": {"ssid_2g": "LabNet-2G", "ssid_5g": "LabNet-5G", "security": "WPA2-PSK"},
            "remote_management": {"ssh_enabled": False, "web_admin_port": 8443},
        }

        self.dotenv_decoy = "\n".join(
            [
                "# BLOG & IOT PORTAL CONFIG (SIMULATED)",
                "APP_ENV=portal-sim",
                "DB_HOST=127.0.0.1",
                "DB_PORT=5432",
                "DB_NAME=portal_sim_db",
                "DB_USER=portal_sim_user",
                "DB_PASSWORD=SIMULATED_NON_PROD_SECRET_0001",
                "IOT_API_KEY=SIMULATED_NON_PROD_KEY_0001",
            ]
        )
        self.config_json_decoy: dict[str, Any] = {
            "service": "blog-iot-portal",
            "environment": "simulation",
            "endpoints": {"blog": "/blog", "api": "/api/v1/status", "device": "/api/v1/device/status"},
            "device": {"model": self.device_config["device_model"], "firmware": self.device_config["firmware_version"]},
        }

    def record_event(self, event: dict[str, Any]) -> None:
        """Append event to in-memory ring buffer and emit structured JSON to stdout."""
        enriched = {"timestamp": utc_now_iso(), **event}
        with self.lock:
            self.events.append(enriched)
            self.path_hits[str(enriched.get("path", ""))] += 1
            self.ip_hits[str(enriched.get("client_ip", "unknown"))] += 1
        print(json.dumps(enriched, ensure_ascii=True), flush=True)

    def create_session(self, username: str, role: str) -> str:
        """Create a synthetic session token in memory."""
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = {"username": username, "role": role, "created_at": utc_now_iso()}
        return token

    def get_session(self, token: str | None) -> dict[str, Any] | None:
        """Retrieve a synthetic session by token."""
        if not token:
            return None
        with self.lock:
            return self.sessions.get(token)

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        """Register a synthetic user account in memory."""
        clean = username.strip()[:40]
        if not clean or not password:
            return False, "Username and password are required."
        with self.lock:
            if clean in self.users:
                return False, "Username already exists."
            self.users[clean] = {"password_hash": sha256_short(password), "role": "user"}
        return True, "Account registered."

    def verify_login(self, username: str, password: str, client_ip: str) -> tuple[bool, str]:
        """Verify credentials against in-memory synthetic accounts."""
        clean = username.strip()
        with self.lock:
            user = self.users.get(clean)
            if user is None or user["password_hash"] != sha256_short(password):
                self.failed_logins_by_ip[client_ip] += 1
                return False, "Invalid username or password."
            return True, user["role"]

    def add_article(self, title: str, category: str, author: str, body: str) -> dict[str, Any]:
        """Create a new article in memory."""
        clean_cat = category.strip().lower()
        if clean_cat not in {"tech", "iot"}:
            clean_cat = "tech"
        with self.lock:
            art = {
                "id": self.next_article_id,
                "title": title.strip()[:140] or "Untitled Entry",
                "category": clean_cat,
                "author": author.strip()[:40] or "guest",
                "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "summary": body.strip()[:140] or "Summary entry.",
                "body": body.strip()[:2000] or "Body entry.",
            }
            self.next_article_id += 1
            self.articles.insert(0, art)
            return dict(art)
        
    def update_device_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update whitelisted fields of the synthetic IoT gateway config in memory."""
        with self.lock:
            if "wan_mode" in updates and updates["wan_mode"] in {"dhcp", "static", "pppoe"}:
                self.device_config["wan"]["mode"] = str(updates["wan_mode"])
            if "wan_ip" in updates and updates["wan_ip"]:
                self.device_config["wan"]["ip_address"] = str(updates["wan_ip"])[:45]
            if "lan_ip" in updates and updates["lan_ip"]:
                self.device_config["lan"]["ip_address"] = str(updates["lan_ip"])[:45]
            if "ssid_2g" in updates and updates["ssid_2g"]:
                self.device_config["wifi"]["ssid_2g"] = str(updates["ssid_2g"])[:64]
            if "ssid_5g" in updates and updates["ssid_5g"]:
                self.device_config["wifi"]["ssid_5g"] = str(updates["ssid_5g"])[:64]
            if "wifi_security" in updates and updates["wifi_security"] in {"WPA2-PSK", "WPA3-SAE", "Open"}:
                self.device_config["wifi"]["security"] = str(updates["wifi_security"])
            if "ssh_enabled" in updates:
                self.device_config["remote_management"]["ssh_enabled"] = bool(updates["ssh_enabled"])
            if "firmware_channel" in updates and updates["firmware_channel"] in {"stable", "beta", "canary"}:
                self.device_config["firmware_version"] = f"v3.9.0-{updates['firmware_channel']}"
            return json.loads(json.dumps(self.device_config))

    def snapshot(self) -> dict[str, Any]:
        """Return summary statistics."""
        with self.lock:
            return {
                "status": "ok",
                "started_at": self.started_at,
                "total_events": len(self.events),
                "unique_ips": len(self.ip_hits),
                "top_paths": self.path_hits.most_common(15),
                "top_ips": self.ip_hits.most_common(10),
                "failed_login_ips": dict(self.failed_logins_by_ip),
                "articles_count": len(self.articles),
                "active_sessions": len(self.sessions),
            }


def render_html(title: str, body_html: str, session_user: str | None = None) -> bytes:
    """Render an HTML document with safe escaping."""
    auth_nav = (
        f"<span><strong>{html.escape(session_user)}</strong> | <a href='/logout'>Logout</a></span>"
        if session_user
        else "<span><a href='/login'>Login</a> | <a href='/register'>Register</a> | <a href='/signup'>Signup</a></span>"
    )
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)} - Portal</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }}
    header {{ background: #1e293b; color: #f8fafc; padding: 0.8rem 1.5rem; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 0.5rem; }}
    header a {{ color: #e2e8f0; text-decoration: none; margin-right: 0.85rem; font-size: 0.9rem; }}
    header a:hover {{ color: #ffffff; text-decoration: underline; }}
    main {{ max-width: 960px; margin: 1.5rem auto; padding: 0 1rem; }}
    .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }}
    .notice {{ background: #eff6ff; border-left: 4px solid #2563eb; padding: 0.7rem 1rem; margin-bottom: 1rem; }}
    .error {{ background: #fef2f2; border-left: 4px solid #dc2626; padding: 0.7rem 1rem; margin-bottom: 1rem; }}
    label {{ display: block; margin-top: 0.65rem; font-weight: bold; font-size: 0.9rem; }}
    input, select, textarea {{ width: 100%; max-width: 480px; padding: 0.45rem; margin-top: 0.25rem; border: 1px solid #cbd5e1; border-radius: 4px; }}
    button {{ margin-top: 0.85rem; padding: 0.5rem 1rem; background: #0f172a; color: #ffffff; border: none; border-radius: 4px; cursor: pointer; }}
    pre {{ background: #0f172a; color: #f8fafc; padding: 0.9rem; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; }}
    footer {{ max-width: 960px; margin: 2rem auto; padding: 0 1rem; font-size: 0.8rem; color: #475569; }}
    footer a {{ color: #334155; margin-right: 0.75rem; }}
  </style>
</head>
<body>
  <header>
    <div>
      <a href="/"><strong>Home</strong></a>
      <a href="/blog">Blog</a>
      <a href="/category/tech">Tech</a>
      <a href="/category/iot">IoT</a>
      <a href="/articles/101">Article #101</a>
      <a href="/posts/new">New Post</a>
      <a href="/posts/list">Post List</a>
      <a href="/admin">Admin</a>
      <a href="/iot/admin">IoT Admin</a>
    </div>
    <div>{auth_nav}</div>
  </header>
  <main>
    <div class="card">
      <h1 style="margin-top:0;">{html.escape(title)}</h1>
      {body_html}
    </div>
  </main>
  <footer>
    <a href="/robots.txt">/robots.txt</a>
    <a href="/sitemap.xml">/sitemap.xml</a>
    <a href="/feed.xml">/feed.xml</a>
    <a href="/rss.xml">/rss.xml</a>
    <a href="/api/v1/status">/api/v1/status</a>
    <a href="/api/v1/device/status">/api/v1/device/status</a>
    <a href="/wp-login.php">/wp-login.php</a>
    <a href="/boaform/admin/formLogin">/boaform/admin/formLogin</a>
    <a href="/cgi-bin/luci">/cgi-bin/luci</a>
  </footer>
</body>
</html>"""
    return doc.encode("utf-8")


class BlogIoTPortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Medium-Interaction Blog + IoT Portal honeypot."""

    state: BlogIoTPortalState
    server_version = "PortalHTTP/2.4"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress stderr output; structured JSON events are emitted explicitly."""
        return

    def _client_ip(self) -> str:
        """Extract real client IP from Nginx X-Real-IP header with safe fallback."""
        real_ip = (self.headers.get("X-Real-IP") or "").strip()
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass

        xff = (self.headers.get("X-Forwarded-For") or "").strip()
        if xff:
            first_hop = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(first_hop)
                return first_hop
            except ValueError:
                pass

        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _cookies(self) -> dict[str, str]:
        raw = self.headers.get("Cookie", "")
        out: dict[str, str] = {}
        for item in raw.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _session(self) -> dict[str, Any] | None:
        return self.state.get_session(self._cookies().get("portal_session"))

    def _read_body(self) -> tuple[bytes, str | None]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return b"", None
        try:
            length = int(raw_len)
        except ValueError:
            return b"", "Invalid Content-Length"
        if length < 0 or length > 65536:
            return b"", "Payload length out of range"
        return self.rfile.read(length), None

    def _parse_payload(self, raw_body: bytes) -> dict[str, Any]:
        if not raw_body:
            return {}
        text = raw_body.decode("utf-8", errors="replace")
        ctype = self.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, dict) else {"_json": parsed}
            except json.JSONDecodeError:
                return {"_malformed_json": text[:300]}
        qs = parse_qs(text, keep_blank_values=True)
        return {k: v[0] if len(v) == 1 else v for k, v in qs.items()}

    def _summarize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for k, v in list(payload.items())[:20]:
            key = str(k)[:50]
            if any(word in key.lower() for word in ("pass", "secret", "token", "key", "pwd")):
                val = str(v)
                summary[key] = {"redacted": True, "length": len(val), "sha256_prefix": sha256_short(val, 8)}
            else:
                summary[key] = str(v)[:160]
        return summary

    def _send_raw(
        self,
        status_code: int,
        content_type: str,
        body: bytes,
        headers: dict[str, str] | None = None,
        allow_body: bool = True,
    ) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if allow_body and self.command != "HEAD":
            self.wfile.write(body)

    def _send_html(
        self,
        status_code: int,
        title: str,
        body_html: str,
        session_user: str | None = None,
        headers: dict[str, str] | None = None,
        allow_body: bool = True,
    ) -> None:
        raw = render_html(title, body_html, session_user=session_user)
        self._send_raw(status_code, "text/html; charset=utf-8", raw, headers=headers, allow_body=allow_body)

    def _send_json(
        self,
        status_code: int,
        data: dict[str, Any],
        headers: dict[str, str] | None = None,
        allow_body: bool = True,
    ) -> None:
        raw = json.dumps(data, ensure_ascii=True, indent=2).encode("utf-8")
        self._send_raw(status_code, "application/json; charset=utf-8", raw, headers=headers, allow_body=allow_body)

    def _log_event(
        self,
        status_code: int,
        outcome: str,
        payload_dict: dict[str, Any] | None = None,
        payload_summary: dict[str, Any] | None = None,
    ) -> None:
        parsed = urlparse(self.path)
        client_ip = self._client_ip()
        ua = self.headers.get("User-Agent", "")
        sess = self._session()
        fp_data = self.state.fingerprinter.fingerprint(
            client_ip=client_ip,
            method=self.command,
            path=parsed.path,
            raw_headers=list(self.headers.items()),
            arrival_monotonic=time.monotonic(),
        )
        intel_data = self.state.osint_engine.analyze(
            client_ip=client_ip,
            user_agent=ua,
            raw_query=parsed.query,
            payload_dict=payload_dict or {},
        )
        self.state.record_event(
            {
                "event_type": "http_request",
                "client_ip": client_ip,
                "method": self.command,
                "path": parsed.path,
                "query": parsed.query[:300],
                "status_code": status_code,
                "outcome": outcome,
                "user_agent": ua[:250],
                "session_user": sess["username"] if sess else None,
                "payload": payload_summary or {},
                "comm_fingerprint": fp_data,
                "threat_intel": intel_data,
            }
        )

    def do_HEAD(self) -> None:
        self._dispatch(allow_body=False)

    def do_GET(self) -> None:
        self._dispatch(allow_body=True)

    def do_POST(self) -> None:
        self._dispatch(allow_body=True)

    def do_PUT(self) -> None:
        self._dispatch(allow_body=True)

    def do_DELETE(self) -> None:
        self._send_json(405, {"error": "Method Not Allowed", "allowed": ["GET", "HEAD", "POST"]}, {"Allow": "GET, HEAD, POST"})
        self._log_event(405, "method_not_allowed")

    def _render_articles(self, items: list[dict[str, Any]]) -> str:
        if not items:
            return "<p>No articles in this category.</p>"
        return "".join(
            f"<div style='border-bottom:1px solid #e2e8f0;padding:0.75rem 0;'>"
            f"<a href='/articles/{a['id']}' style='font-size:1.05rem;font-weight:bold;color:#0f172a;'>{html.escape(str(a['title']))}</a>"
            f"<p style='margin:0.3rem 0;color:#334155;'>{html.escape(str(a['summary']))}</p>"
            f"<div style='font-size:0.8rem;color:#64748b;'>[{html.escape(str(a['category']))}] by {html.escape(str(a['author']))} at {html.escape(str(a['published_at']))}</div></div>"
            for a in items
        )

    def _dispatch(self, allow_body: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        sess = self._session()
        session_user = sess["username"] if sess else None

        raw_body = b""
        if self.command in {"POST", "PUT"}:
            raw_body, err = self._read_body()
            if err:
                self._send_json(400, {"error": err}, allow_body=allow_body)
                self._log_event(400, "bad_request", payload_summary={"reason": err})
                return

        payload = self._parse_payload(raw_body) if raw_body else {}
        payload_summary = self._summarize_payload(payload) if payload else {}

        # 1. Blog & discovery routes
        if path == "/robots.txt":
            txt = (
                "User-agent: *\nAllow: /\nAllow: /blog\nAllow: /sitemap.xml\nAllow: /feed.xml\nAllow: /rss.xml\n"
                "Disallow: /admin\nDisallow: /posts/new\nDisallow: /iot/\nDisallow: /api/v1/device/\n"
                "Disallow: /wp-login.php\nDisallow: /boaform/admin/formLogin\nDisallow: /cgi-bin/luci\n"
                "Sitemap: /sitemap.xml\n"
            ).encode("utf-8")
            self._send_raw(200, "text/plain; charset=utf-8", txt, allow_body=allow_body)
            self._log_event(200, "robots_txt", payload, payload_summary)
            return

        if path == "/sitemap.xml":
            locs = ["/", "/blog", "/category/tech", "/category/iot"] + [f"/articles/{a['id']}" for a in self.state.articles]
            body_xml = "\n".join(f"  <url><loc>{loc}</loc></url>" for loc in locs)
            xml = f"<?xml version='1.0' encoding='UTF-8'?>\n<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>\n{body_xml}\n</urlset>\n".encode("utf-8")
            self._send_raw(200, "application/xml; charset=utf-8", xml, allow_body=allow_body)
            self._log_event(200, "sitemap_xml", payload, payload_summary)
            return

        if path in {"/feed.xml", "/rss.xml"}:
            items_xml = "\n".join(
                f"  <item><title>{html.escape(str(a['title']))}</title><link>/articles/{a['id']}</link></item>"
                for a in self.state.articles
            )
            rss = f"<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel><title>Portal Feed</title>\n{items_xml}\n</channel></rss>".encode("utf-8")
            self._send_raw(200, "application/rss+xml; charset=utf-8", rss, allow_body=allow_body)
            self._log_event(200, "feed_xml", payload, payload_summary)
            return

        if path in {"/", "/blog", "/posts/list"}:
            if self.command not in {"GET", "HEAD"}:
                self._send_html(405, "405 Method Not Allowed", "<p>Use GET or HEAD.</p>", session_user, {"Allow": "GET, HEAD"}, allow_body)
                self._log_event(405, "method_not_allowed", payload, payload_summary)
                return
            self._send_html(200, "Portal Blog", self._render_articles(self.state.articles), session_user, allow_body=allow_body)
            self._log_event(200, "blog_index", payload, payload_summary)
            return

        if path.startswith("/category/"):
            cat = path.split("/category/", 1)[1].strip("/").lower()
            if cat not in {"tech", "iot"}:
                self._send_html(404, "404 Not Found", f"<p>Category not found: {html.escape(cat)}</p>", session_user, allow_body=allow_body)
                self._log_event(404, "category_not_found", payload, {"category": cat})
                return
            matched = [a for a in self.state.articles if a["category"] == cat]
            self._send_html(200, f"Category: {cat.upper()}", self._render_articles(matched), session_user, allow_body=allow_body)
            self._log_event(200, "category_view", payload, {"category": cat})
            return

        if path.startswith("/articles/"):
            raw_id = path.split("/articles/", 1)[1].strip("/")
            try:
                art_id = int(raw_id)
            except ValueError:
                self._send_html(400, "400 Bad Request", "<p>Invalid article ID.</p>", session_user, allow_body=allow_body)
                self._log_event(400, "invalid_article_id", payload, {"raw_id": raw_id})
                return
            art = next((a for a in self.state.articles if a["id"] == art_id), None)
            if not art:
                self._send_html(404, "404 Not Found", "<p>Article not found.</p>", session_user, allow_body=allow_body)
                self._log_event(404, "article_not_found", payload, {"article_id": art_id})
                return
            detail = (
                f"<div style='font-size:0.85rem;color:#64748b;'>Category: {html.escape(str(art['category']))} | "
                f"Author: {html.escape(str(art['author']))} | Published: {html.escape(str(art['published_at']))}</div>"
                f"<p style='line-height:1.7;margin-top:0.8rem;'>{html.escape(str(art['body']))}</p>"
            )
            self._send_html(200, str(art["title"]), detail, session_user, allow_body=allow_body)
            self._log_event(200, "article_detail", payload, {"article_id": art_id})
            return

        # 2. Auth & account routes
        if path in {"/login", "/boaform/admin/formLogin", "/wp-login.php"}:
            if self.command == "GET":
                form = (
                    f"<form method='POST' action='{html.escape(path)}'>"
                    "<label>Username</label><input type='text' name='username' required>"
                    "<label>Password</label><input type='password' name='password' required>"
                    "<button type='submit'>Sign In</button></form>"
                )
                self._send_html(200, f"Login ({path})", form, session_user, allow_body=allow_body)
                self._log_event(200, "login_form", payload, payload_summary)
                return
            if self.command == "POST":
                user = str(payload.get("username") or payload.get("user_login") or payload.get("inputStr") or "")
                pwd = str(payload.get("password") or payload.get("user_pass") or payload.get("inputPwd") or "")
                ok, info = self.state.verify_login(user, pwd, self._client_ip())
                if ok:
                    token = self.state.create_session(user, info)
                    self._send_html(
                        302,
                        "Redirecting",
                        "<p>Signed in.</p>",
                        user,
                        headers={"Location": "/admin/dashboard", "Set-Cookie": f"portal_session={token}; HttpOnly; Path=/"},
                        allow_body=allow_body,
                    )
                    self._log_event(302, "login_success_decoy", payload, payload_summary)
                else:
                    self._send_html(
                        401,
                        "401 Unauthorized",
                        f"<div class='error'>{html.escape(info)}</div>",
                        session_user,
                        headers={"WWW-Authenticate": 'Basic realm="PortalAuth"'},
                        allow_body=allow_body,
                    )
                    self._log_event(401, "login_failed", payload, payload_summary)
                return
            self._send_html(405, "405 Method Not Allowed", "<p>Use GET or POST.</p>", session_user, {"Allow": "GET, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        if path == "/logout":
            self._send_html(302, "Logged Out", "<p>Signed out.</p>", None, headers={"Location": "/", "Set-Cookie": "portal_session=; Max-Age=0; Path=/"}, allow_body=allow_body)
            self._log_event(302, "logout", payload, payload_summary)
            return

        if path in {"/register", "/signup"}:
            if self.command == "GET":
                form = (
                    f"<form method='POST' action='{html.escape(path)}'>"
                    "<label>Username</label><input type='text' name='username' required>"
                    "<label>Password</label><input type='password' name='password' required>"
                    "<button type='submit'>Register</button></form>"
                )
                self._send_html(200, "Account Registration", form, session_user, allow_body=allow_body)
                self._log_event(200, "register_form", payload, payload_summary)
                return
            if self.command == "POST":
                ok, msg = self.state.register_user(str(payload.get("username", "")), str(payload.get("password", "")))
                self._send_html(200 if ok else 400, "Registration", f"<div class='notice'>{html.escape(msg)}</div>", session_user, allow_body=allow_body)
                self._log_event(200 if ok else 400, "register_attempt", payload, payload_summary)
                return
            self._send_html(405, "405 Method Not Allowed", "<p>Use GET or POST.</p>", session_user, {"Allow": "GET, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        if path == "/password/reset":
            if self.command == "GET":
                form = "<form method='POST' action='/password/reset'><label>Username</label><input type='text' name='account' required><button type='submit'>Request Reset</button></form>"
                self._send_html(200, "Password Reset", form, session_user, allow_body=allow_body)
                self._log_event(200, "password_reset_form", payload, payload_summary)
                return
            if self.command == "POST":
                self._send_html(200, "Password Reset", "<div class='notice'>Password reset request accepted in simulation.</div>", session_user, allow_body=allow_body)
                self._log_event(200, "password_reset_post", payload, payload_summary)
                return
            self._send_html(405, "405 Method Not Allowed", "<p>Use GET or POST.</p>", session_user, {"Allow": "GET, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        # 3. Post creation & admin routes
        if path == "/posts/new":
            if self.command == "GET":
                form = (
                    "<form method='POST' action='/posts/new'>"
                    "<label>Title</label><input type='text' name='title' required>"
                    "<label>Category</label><select name='category'><option value='tech'>tech</option><option value='iot'>iot</option></select>"
                    "<label>Body</label><textarea name='body' rows='4' required></textarea>"
                    "<button type='submit'>Publish Post</button></form>"
                )
                self._send_html(200, "New Post", form, session_user, allow_body=allow_body)
                self._log_event(200, "new_post_form", payload, payload_summary)
                return
            if self.command == "POST":
                art = self.state.add_article(str(payload.get("title", "")), str(payload.get("category", "tech")), session_user or "guest", str(payload.get("body", "")))
                self._send_html(200, "Post Published", f"<div class='notice'>Created article #<a href='/articles/{art['id']}'>{art['id']}</a>.</div>", session_user, allow_body=allow_body)
                self._log_event(200, "post_created", payload, {"article_id": art["id"], **payload_summary})
                return
            self._send_html(405, "405 Method Not Allowed", "<p>Use GET or POST.</p>", session_user, {"Allow": "GET, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        if path in {"/admin", "/admin/dashboard", "/admin/posts"}:
            if self.command not in {"GET", "HEAD"}:
                self._send_html(405, "405 Method Not Allowed", "<p>Use GET or HEAD.</p>", session_user, {"Allow": "GET, HEAD"}, allow_body)
                self._log_event(405, "method_not_allowed", payload, payload_summary)
                return
            snap = self.state.snapshot()
            self._send_html(200, f"Admin ({path})", f"<pre>{html.escape(json.dumps(snap, indent=2))}</pre>", session_user, allow_body=allow_body)
            self._log_event(200, "admin_view", payload, payload_summary)
            return

        # 4. IoT device management routes
        if path in {"/iot/admin", "/iot/status", "/iot/network", "/iot/wifi", "/iot/firmware", "/cgi-bin/luci"}:
            if self.command == "GET":
                cfg = self.state.device_config
                form = (
                    f"<form method='POST' action='{html.escape(path)}'>"
                    "<label>WAN Mode</label><select name='wan_mode'><option value='dhcp'>dhcp</option><option value='static'>static</option><option value='pppoe'>pppoe</option></select>"
                    f"<label>WAN IP</label><input type='text' name='wan_ip' value='{html.escape(cfg['wan']['ip_address'])}'>"
                    f"<label>LAN IP</label><input type='text' name='lan_ip' value='{html.escape(cfg['lan']['ip_address'])}'>"
                    f"<label>2.4G SSID</label><input type='text' name='ssid_2g' value='{html.escape(cfg['wifi']['ssid_2g'])}'>"
                    f"<label>5G SSID</label><input type='text' name='ssid_5g' value='{html.escape(cfg['wifi']['ssid_5g'])}'>"
                    "<label>Wi-Fi Security</label><select name='wifi_security'><option value='WPA2-PSK'>WPA2-PSK</option><option value='WPA3-SAE'>WPA3-SAE</option><option value='Open'>Open</option></select>"
                    "<label>Firmware Channel</label><select name='firmware_channel'><option value='stable'>stable</option><option value='beta'>beta</option><option value='canary'>canary</option></select>"
                    "<label>SSH Management</label><select name='ssh_enabled'><option value='false'>false</option><option value='true'>true</option></select>"
                    "<button type='submit'>Apply IoT Settings</button></form>"
                    f"<pre>{html.escape(json.dumps(cfg, indent=2))}</pre>"
                )
                self._send_html(200, f"IoT Gateway ({path})", form, session_user, allow_body=allow_body)
                self._log_event(200, "iot_view", payload, payload_summary)
                return
            if self.command == "POST":
                norm = dict(payload)
                if "ssh_enabled" in norm:
                    norm["ssh_enabled"] = str(norm["ssh_enabled"]).lower() in {"1", "true", "yes", "on"}
                updated = self.state.update_device_config(norm)
                self._send_html(200, "IoT Settings Updated", f"<div class='notice'>Updated in memory.</div><pre>{html.escape(json.dumps(updated, indent=2))}</pre>", session_user, allow_body=allow_body)
                self._log_event(200, "iot_updated", payload, payload_summary)
                return
            self._send_html(405, "405 Method Not Allowed", "<p>Use GET or POST.</p>", session_user, {"Allow": "GET, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        # 5. API & recon decoy endpoints
        if path == "/api/v1/status":
            self._send_json(200, {"status": "ok", "service": "blog-iot-portal", "articles": len(self.state.articles)}, allow_body=allow_body)
            self._log_event(200, "api_status", payload, payload_summary)
            return

        if path == "/api/v1/posts":
            if self.command in {"GET", "HEAD"}:
                self._send_json(200, {"posts": self.state.articles}, allow_body=allow_body)
                self._log_event(200, "api_posts_get", payload, payload_summary)
                return
            if self.command == "POST":
                art = self.state.add_article(str(payload.get("title", "")), str(payload.get("category", "tech")), session_user or "api_client", str(payload.get("body", "")))
                self._send_json(200, {"status": "created", "post": art}, allow_body=allow_body)
                self._log_event(200, "api_posts_post", payload, {"article_id": art["id"], **payload_summary})
                return
            self._send_json(405, {"error": "Method Not Allowed"}, {"Allow": "GET, HEAD, POST"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        if path == "/api/v1/auth/login":
            if self.command != "POST":
                self._send_json(405, {"error": "Method Not Allowed"}, {"Allow": "POST"}, allow_body)
                self._log_event(405, "method_not_allowed", payload, payload_summary)
                return
            user = str(payload.get("username", ""))
            pwd = str(payload.get("password", ""))
            ok, info = self.state.verify_login(user, pwd, self._client_ip())
            if ok:
                token = self.state.create_session(user, info)
                self._send_json(200, {"status": "ok", "token": token, "role": info}, allow_body=allow_body)
                self._log_event(200, "api_login_ok", payload, payload_summary)
            else:
                self._send_json(401, {"error": info}, {"WWW-Authenticate": "Bearer"}, allow_body)
                self._log_event(401, "api_login_fail", payload, payload_summary)
            return

        if path == "/api/v1/device/status":
            cfg = self.state.device_config
            self._send_json(200, {"model": cfg["device_model"], "firmware": cfg["firmware_version"], "hostname": cfg["hostname"]}, allow_body=allow_body)
            self._log_event(200, "api_device_status", payload, payload_summary)
            return

        if path == "/api/v1/device/config":
            if self.command in {"GET", "HEAD"}:
                self._send_json(200, self.state.device_config, allow_body=allow_body)
                self._log_event(200, "api_device_cfg_get", payload, payload_summary)
                return
            if self.command in {"POST", "PUT"}:
                updated = self.state.update_device_config(payload)
                self._send_json(200, {"status": "updated", "config": updated}, allow_body=allow_body)
                self._log_event(200, "api_device_cfg_put", payload, payload_summary)
                return
            self._send_json(405, {"error": "Method Not Allowed"}, {"Allow": "GET, HEAD, POST, PUT"}, allow_body)
            self._log_event(405, "method_not_allowed", payload, payload_summary)
            return

        if path == "/.env":
            self._send_raw(200, "text/plain; charset=utf-8", self.state.dotenv_decoy.encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "decoy_dotenv", payload, payload_summary)
            return

        if path == "/config.json":
            self._send_json(200, self.state.config_json_decoy, allow_body=allow_body)
            self._log_event(200, "decoy_config_json", payload, payload_summary)
            return

        if path == "/backup.zip":
            self._send_json(403, {"error": "Forbidden"}, allow_body=allow_body)
            self._log_event(403, "decoy_backup_zip", payload, payload_summary)
            return

        if path in {"/actuator", "/actuator/env"}:
            self._send_json(200, {"profiles": ["simulation"], "service": "blog-iot-portal"}, allow_body=allow_body)
            self._log_event(200, "decoy_actuator", payload, payload_summary)
            return

        if path == "/server-status":
            self._send_json(501, {"error": "Not Implemented"}, allow_body=allow_body)
            self._log_event(501, "decoy_server_status", payload, payload_summary)
            return

        self._send_html(404, "404 Not Found", f"<p>Not found: <code>{html.escape(path)}</code></p>", session_user, allow_body=allow_body)
        self._log_event(404, "not_found", payload, payload_summary)


def run_blog_iot_honeypot(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the Medium-Interaction Blog + IoT Portal honeypot server."""
    state = BlogIoTPortalState()
    BlogIoTPortalHandler.state = state
    httpd = ThreadingHTTPServer((host, port), BlogIoTPortalHandler)
    state.record_event({"event_type": "server_start", "client_ip": host, "method": "INIT", "path": "/", "status_code": 200, "outcome": "listening", "payload": {"port": port}})
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        state.record_event({"event_type": "server_stop", "client_ip": host, "method": "SHUTDOWN", "path": "/", "status_code": 200, "outcome": "stopped", "payload": state.snapshot()})


if __name__ == "__main__":
    run_blog_iot_honeypot(host="0.0.0.0", port=8080)