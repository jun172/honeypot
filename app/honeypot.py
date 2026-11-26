#!/usr/bin/env python3
"""
Yaho! News-style Medium-Interaction Honeypot with SQLite & Decoy Vulnerabilities.

Simulates a Japanese news portal backed by SQLite (/tmp/portal_news.db) with
intentional, safe-to-host decoy vulnerabilities (SQLi, Reflected/Stored XSS,
IDOR, Path Traversal/LFI, SSRF metadata decoy, Command Injection / Next.js RSC
RCE emulation) while emitting structured JSON telemetry to stdout.
No real OS commands are executed and no external network calls are made.
"""

from __future__ import annotations

import base64
import binascii
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


_PROXY_INTERNAL_HEADERS: frozenset[str] = frozenset(
    {
        "x-real-ip",
        "x-real-port",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-original-port",
        "x-proxy-verified",
        "x-ssl-protocol",
        "x-ssl-cipher",
        "x-ssl-server-name",
    }
)

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
_JS_NOISE_DOMAINS: frozenset[str] = frozenset(
    {
        "process.mainmodule.require",
        "c.spawn",
        "n.socket",
        "cl.connect",
        "cl.pipe",
        "s.stdin",
        "s.stdout.pipe",
        "s.stderr.pipe",
        "child_process.exec",
        "child_process.spawn",
    }
)
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|\b[0-9a-fA-F]{24,}\b")

_ECHO_RE = re.compile(
    r"""(?:^|[\s;|&`(])(?:echo|printf)\s+(?:-[neE]+\s+)?["']?([A-Za-z0-9_./:-]{1,120})["']?""",
    re.IGNORECASE,
)
_PHP_ECHO_RE = re.compile(
    r"""(?:echo|print)\s*\(?\s*["']([A-Za-z0-9_./:-]{1,120})["']\s*\)?""",
    re.IGNORECASE,
)

_TECHNIQUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "nextjs_rsc_rce",
        re.compile(
            r"(?:\$1:__proto__:then|resolved_model|_response|_prefix|process\.mainModule|child_process|next-action)",
            re.IGNORECASE,
        ),
    ),
    (
        "rce_cmd_injection",
        re.compile(
            r"(?:\bwget\b|\bcurl\b|\bchmod\b|\b/bin/sh\b|\b/bin/bash\b|\bnc\b|\bnetcat\b|\bwhoami\b|\buname\b|;\s*(?:id|sh|bash|wget|curl)\b|\$\([^)]+\)|`[^`]+`)",
            re.IGNORECASE,
        ),
    ),
    (
        "log4j_jndi",
        re.compile(r"\$\{\s*jndi\s*:(?:ldap|ldaps|rmi|dns|iiop)s?://", re.IGNORECASE),
    ),
    (
        "shellshock",
        re.compile(r"\(\)\s*\{[^}]*\}\s*;?", re.IGNORECASE),
    ),
    (
        "sqli",
        re.compile(
            r"(?:\bunion\b(?:\s+all)?\s+\bselect\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\band\b\s+1\s*=\s*1|\bsleep\s*\(|\bbenchmark\s*\(|\bsqlite_master\b|\bextractvalue\s*\(|\bupdatexml\s*\(|'\s*--)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(
            r"(?:<script\b|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|document\.cookie|<svg\b|<iframe\b|alert\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        re.compile(
            r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|/etc/passwd|/etc/shadow|/proc/self/environ|portal_news\.db)",
            re.IGNORECASE,
        ),
    ),
    (
        "ssrf_cloud_metadata",
        re.compile(
            r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|/latest/meta-data/|computeMetadata/v1)",
            re.IGNORECASE,
        ),
    ),
    (
        "php_eval_rce",
        re.compile(
            r"(?:<\?php|eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|proc_open\s*\(|popen\s*\(|base64_decode\s*\(|eval-stdin\.php)",
            re.IGNORECASE,
        ),
    ),
    (
        "thinkphp_rce",
        re.compile(
            r"(?:\\think\\app|\\think\\container|invokefunction|call_user_func_array|s=/index/\think)",
            re.IGNORECASE,
        ),
    ),
    (
        "spring_spel_rce",
        re.compile(
            r"(?:/actuator(?:/env|/heapdump|/jolokia|/gatewayroutes)?|\bT\s*\(\s*java\.lang\.Runtime\b|ProcessBuilder)",
            re.IGNORECASE,
        ),
    ),
    (
        "deserialization",
        re.compile(
            r"(?:rO0AB|aced0005|O:\d+:\"[A-Za-z0-9_\\]+\":\d+:\{|__wakeup|__destruct|java\.io\.ObjectInputStream|ysoserial)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_stuffing",
        re.compile(
            r"(?:/wp-login\.php|/xmlrpc\.php|/boaform/admin/formLogin|/api/v1/auth/login|\b(?:admin|root|guest|test|user)\b.*(?:password|passwd|pwd|token))",
            re.IGNORECASE,
        ),
    ),
    (
        "scanner_recon",
        re.compile(
            r"(?:/\.env|/config\.json|/backup\.zip|/server-status|/wp-admin/admin-ajax\.php|/script\b|/phpinfo\.php|sqlmap|nikto|masscan|zgrab|nuclei|dirbuster|gobuster)",
            re.IGNORECASE,
        ),
    ),
]

CATEGORIES: dict[str, str] = {
    "top": "主要",
    "domestic": "国内",
    "world": "国際",
    "economy": "経済",
    "ent": "エンタメ",
    "sports": "スポーツ",
    "it": "IT",
    "science": "科学",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def display_time_str() -> str:
    """Return formatted UTC timestamp for portal header display."""
    return datetime.now(timezone.utc).strftime("%m/%d(%a) %H:%M UTC")


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


def _clean_printable(text: str) -> str:
    printable = "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable.strip()[:2000]


def _decode_base64_once(token: str) -> str | None:
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
        decoded = raw.decode("utf-8", errors="ignore")
        cleaned = _clean_printable(decoded)
        return cleaned if len(cleaned) >= 4 else None
    except Exception:
        return None


def _decode_base64_candidates(text: str) -> list[str]:
    """Safely attempt 1st and 2nd stage Base64 + URL decoding."""
    out: list[str] = []
    seen: set[str] = set()
    for token in _B64_RE.findall(text)[:25]:
        first = _decode_base64_once(token)
        if first and first not in seen:
            seen.add(first)
            out.append(first)
            # Second stage: URL-unquote and check nested Base64
            stage2_text = unquote(first)
            if stage2_text != first and stage2_text not in seen:
                seen.add(stage2_text)
                out.append(stage2_text)
            for inner_tok in _B64_RE.findall(stage2_text)[:10]:
                second = _decode_base64_once(inner_tok)
                if second and second not in seen:
                    seen.add(second)
                    out.append(second)
    return out


def _decode_hex_candidates(text: str) -> list[str]:
    """Safely attempt hex decoding and keep printable strings."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _HEX_RE.findall(text)[:20]:
        cleaned = match.replace("\\x", "").replace("0x", "")
        if len(cleaned) < 8 or len(cleaned) % 2 != 0:
            continue
        try:
            raw = binascii.unhexlify(cleaned)
            decoded = _clean_printable(raw.decode("utf-8", errors="ignore"))
            if len(decoded) >= 4 and decoded not in seen:
                seen.add(decoded)
                out.append(decoded)
        except Exception:
            continue
    return out


def extract_echo_token(text: str) -> str | None:
    """Extract a safe marker token from echo/printf probe strings."""
    for rx in (_ECHO_RE, _PHP_ECHO_RE):
        m = rx.search(text)
        if m:
            tok = m.group(1).strip()
            if tok:
                return tok[:120]
    return None


class VirtualAttackEmulator:
    """In-memory virtual files and decoy responses without OS or network side effects."""

    def __init__(self) -> None:
        self.passwd_decoy = "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "www-data:x:33:33:www-data:/var/www/html:/usr/sbin/nologin",
                "news_batch:x:1001:1001:News Editorial Batch:/home/news_batch:/bin/bash",
                "sqlite_backup:x:1002:1002:SQLite Snapshot:/var/backups/sqlite:/bin/sh",
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            ]
        )
        self.laravel_env_decoy = "\n".join(
            [
                "APP_NAME=YahoNewsPortal",
                "APP_ENV=production",
                "APP_KEY=base64:SIMULATEDNEWSKEY000000000000000000000000001=",
                "APP_DEBUG=true",
                "DB_CONNECTION=sqlite",
                "DB_DATABASE=/tmp/portal_news.db",
                "EDITORIAL_API_TOKEN=ynp_live_9981203981203981_decoy",
                "AWS_ACCESS_KEY_ID=AKIASIMULATEDNEWS0001",
                "AWS_SECRET_ACCESS_KEY=SIMULATED_NEWS_AWS_SECRET_0001",
                "AWS_DEFAULT_REGION=ap-northeast-1",
            ]
        )
        self.metadata_decoy: dict[str, Any] = {
            "instance-id": "i-09f8e7d6c5b4a3210",
            "local-ipv4": "10.146.0.14",
            "public-hostname": "news-web-prod-01.ap-northeast-1.compute.internal",
            "iam": {
                "role": "news-editorial-prod-role",
                "AccessKeyId": "ASIASIMULATEDMETADATA01",
                "SecretAccessKey": "SIMULATED_METADATA_SECRET_KEY_0001",
                "Token": "IQoJb3JpZ2luX2VjECoaDmFwLW5vcnRoZWFzdC0xSIMULATED",
            },
        }
        self.actuator_env_decoy: dict[str, Any] = {
            "activeProfiles": ["production"],
            "propertySources": [
                {
                    "name": "applicationConfig: [classpath:/application-prod.yml]",
                    "properties": {
                        "spring.datasource.url": {"value": "jdbc:sqlite:/tmp/portal_news.db"},
                        "editorial.jwt.secret": {"value": "SIMULATED_NEWS_JWT_SECRET_2026"},
                    },
                }
            ],
        }


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


class ThreatIntelEngine:
    """Extract IOCs, decode multi-stage Base64/Hex/URL strings, and tag attack techniques."""

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
            "wget",
        ]

    def analyze(
        self,
        client_ip: str,
        user_agent: str,
        raw_path: str,
        raw_query: str,
        raw_headers: list[tuple[str, str]],
        payload_dict: dict[str, Any],
    ) -> dict[str, Any]:
        parts: list[str] = []
        if raw_path:
            parts.append(f"path={unquote(raw_path)}")
        if raw_query:
            parts.append(f"query={unquote(raw_query)}")
        for k, v in list(raw_headers)[:40]:
            parts.append(f"header:{k}={unquote(str(v))}")
        for k, v in list(payload_dict.items())[:50]:
            parts.append(f"{k}={v}")

        raw_text = unquote(unquote("\n".join(parts)))[:16000]
        decoded_b64 = _decode_base64_candidates(raw_text)
        decoded_hex = _decode_hex_candidates(raw_text)

        extra_blocks = decoded_b64 + decoded_hex
        corpus = raw_text + ("\n" + "\n".join(extra_blocks) if extra_blocks else "")

        captured_urls = list(dict.fromkeys(_URL_RE.findall(corpus)))[:30]
        raw_ips = list(dict.fromkeys(_IPV4_RE.findall(corpus)))[:30]
        domains = [
            d
            for d in dict.fromkeys(d.lower() for d in _DOMAIN_RE.findall(corpus))
            if d not in _JS_NOISE_DOMAINS
        ][:30]

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
        matched_urls = [u for u in captured_urls if any(bad in u.lower() for bad in self.known_bad_domains)]
        techniques = [tag for tag, rx in _TECHNIQUE_PATTERNS if rx.search(corpus)]
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
            "attack_techniques": techniques,
            "attack_patterns": techniques,
            "captured_attacker_urls": captured_urls,
            "decoded_base64_texts": decoded_b64,
            "decoded_hex_texts": decoded_hex,
            "c2_candidates": {
                "urls": captured_urls,
                "ips": ip_items,
                "domains": domains,
                "decoded_base64_count": len(decoded_b64),
                "decoded_hex_count": len(decoded_hex),
            },
            "osint_correlation": {
                "mode": "local_in_memory_only",
                "match_count": len(osint_matches),
                "matches": osint_matches,
            },
        }


class NewsSQLiteStore:
    """SQLite database backing the Yaho! News-style portal with intentional SQLi surfaces."""

    def __init__(self, db_path: str = "/tmp/portal_news.db") -> None:
        self.lock = threading.Lock()
        self.db_path = db_path
        try:
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
        except sqlite3.Error:
            self.db_path = ":memory:"
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT NOT NULL,
                    api_token TEXT NOT NULL,
                    internal_note TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    media_name TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    views INTEGER NOT NULL DEFAULT 0,
                    is_pickup INTEGER NOT NULL DEFAULT 1,
                    badge TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL,
                    body TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    article_id INTEGER NOT NULL,
                    author_name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    likes INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                """
            )
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO users (username, password, role, email, api_token, internal_note) VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            "admin",
                            "YahoNewsAdmin2026!",
                            "chief_editor",
                            "admin@news-portal.example.jp",
                            "ynp_tok_admin_9918273645_decoy",
                            "編成デスク統括アカウント（DB管理権限あり）",
                        ),
                        (
                            "desk_kobe",
                            "KobeDesk#1126",
                            "editor",
                            "kobe-desk@news-portal.example.jp",
                            "ynp_tok_editor_5544332211_decoy",
                            "関西支局配信担当・速報テロップ承認権限",
                        ),
                        (
                            "api_sync",
                            "SyncFeed@2026",
                            "service",
                            "feed-bot@news-portal.example.jp",
                            "ynp_tok_bot_7766554433_decoy",
                            "提携メディアRSS自動取込バッチ用",
                        ),
                    ],
                )

            cur.execute("SELECT COUNT(*) FROM articles")
            if cur.fetchone()[0] == 0:
                seed_articles = [
                    (
                        101,
                        "冬の日本海側で大雪警戒 交通機関の乱れに注意",
                        "domestic",
                        "共同通信",
                        "11/26(木) 9:12",
                        48210,
                        1,
                        "速報",
                        "強い冬型の気圧配置の影響で、北日本から西日本の日本海側を中心に大雪となる見込み。",
                        "気象庁によると、上空に強い寒気が流れ込んでいる影響で、日本海側を中心に平地でも積雪が急増する恐れがある。JR各社や高速道路会社は計画運休や予防的通行止めの可能性を呼びかけており、最新の運行情報の確認が求められる。",
                    ),
                    (
                        102,
                        "円相場 1ドル154円台後半で推移 日銀の金融政策に注目",
                        "economy",
                        "時事通信",
                        "11/26(木) 8:55",
                        35900,
                        1,
                        "注目",
                        "東京外国為替市場の円相場は1ドル＝154円台後半を中心に小幅な値動きが続いている。",
                        "26日午前の東京外国為替市場では、米長期金利の動向と来月の日銀金融政策決定会合を見極めたいとの思惑から、1ドル＝154円70銭前後での取引が続いている。市場関係者の間では追加利上げの時期を巡り見方が分かれている。",
                    ),
                    (
                        103,
                        "国内クラウド基盤への自動スキャン急増 専門家が警鐘",
                        "it",
                        "ITmedia NEWS",
                        "11/26(木) 8:40",
                        61420,
                        1,
                        "独自",
                        "公開サーバーやWebフレームワークの既知の脆弱性を狙う自動スキャンが国内外で増加している。",
                        "セキュリティ研究機関の観測によると、未パッチのWebアプリケーションや管理画面ポートを標的とした自動探索通信が前月比で約1.6倍に増加した。専門家は不要ポートの閉鎖とWAF・認証強化の徹底を呼びかけている。",
                    ),
                    (
                        104,
                        "プロ野球 契約更改が本格化 若手主力の大幅昇給相次ぐ",
                        "sports",
                        "スポニチアネックス",
                        "11/26(木) 8:15",
                        29340,
                        1,
                        "",
                        "各球団で契約更改交渉が本格化し、今季ブレークを果たした若手選手に大幅増額提示が続いている。",
                        "セ・パ両リーグの各球団事務所で26日も契約更改交渉が行われ、先発ローテーションを守り抜いた若手投手や主力野手が笑顔で会見に臨んだ。来季のタイトル獲得へ向け早くも意欲を見せている。",
                    ),
                    (
                        105,
                        "欧州連合 AI規制法の運用指針案を公表 企業対応が焦点に",
                        "world",
                        "ロイター",
                        "11/26(木) 7:50",
                        22180,
                        1,
                        "",
                        "欧州委員会は生成AIを含む高リスクAIシステムに関する新たな運用ガイドライン案を示した。",
                        "欧州委員会は域内でAIサービスを提供する企業に対し、学習データの透明性確保とリスク評価報告を求める実務指針案を公表した。日本企業を含むグローバルIT各社にも影響が及ぶ見通しだ。",
                    ),
                    (
                        106,
                        "年末商戦に向け百貨店各社が福袋予約を開始 体験型が人気",
                        "economy",
                        "毎日新聞",
                        "11/26(木) 7:30",
                        18750,
                        1,
                        "",
                        "大手百貨店各社が2027年新春福袋の先行予約を本格化させ、家族で楽しめる体験型企画が好調だ。",
                        "物価高が続くなかでも特別感のある消費への需要は底堅く、宿泊体験や限定グルメを組み合わせた福袋への応募が例年を上回るペースで伸びている。",
                    ),
                    (
                        107,
                        "人気ドラマ最終回 放送直後からSNSで考察投稿が殺到",
                        "ent",
                        "オリコン",
                        "11/26(木) 7:05",
                        41200,
                        1,
                        "話題",
                        "昨夜放送された連続ドラマの最終回を受け、関連ワードがSNSトレンド上位を独占した。",
                        "最終盤の伏線回収とサプライズ演出に対し、視聴者からは「鳥肌が立った」「続編を期待したい」といった感想が相次ぎ、見逃し配信の再生数も過去最高ペースを記録している。",
                    ),
                    (
                        108,
                        "次世代全固体電池の量産技術に前進 航続距離2割向上へ",
                        "science",
                        "日刊工業新聞",
                        "11/26(木) 6:45",
                        27640,
                        1,
                        "",
                        "国内研究チームが全固体電池の界面抵抗を低減する新手法を開発し、充電時間の短縮に道を開いた。",
                        "研究グループは独自の固体電解質コーティング技術により、従来課題だった充放電サイクル時の劣化を大幅に抑制することに成功した。車載向け実用化に向けた実証試験が来春にも始まる。",
                    ),
                ]
                cur.executemany(
                    """
                    INSERT INTO articles (id, title, category, media_name, published_at, views, is_pickup, badge, summary, body)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    seed_articles,
                )

            cur.execute("SELECT COUNT(*) FROM comments")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO comments (article_id, author_name, content, likes, created_at) VALUES (?, ?, ?, ?, ?)",
                    [
                        (101, "hyogo_commuter", "朝のJR線も少し遅れが出ていました。早めの移動が安心ですね。", 142, "11/26 9:18"),
                        (103, "sec_engineer", "海外IPからの自動スキャンは24時間ずっと来ているのでFW設定が必須。", 218, "11/26 8:52"),
                        (102, "market_watcher", "来月の会合までは154〜155円レンジの攻防が続きそう。", 64, "11/26 9:05"),
                    ],
                )
            self.conn.commit()

    def list_articles(self, category: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            if category and category != "top":
                cur.execute(
                    "SELECT * FROM articles WHERE category = ? ORDER BY id DESC LIMIT ?",
                    (category, limit),
                )
            else:
                cur.execute("SELECT * FROM articles ORDER BY is_pickup DESC, id ASC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def ranking_articles(self, limit: int = 5) -> list[dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, title, media_name, views FROM articles ORDER BY views DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_article(self, article_id: int) -> dict[str, Any] | None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE articles SET views = views + 1 WHERE id = ?", (article_id,))
            self.conn.commit()
            cur.execute("SELECT * FROM articles WHERE id = ?", (article_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_comments(self, article_id: int) -> list[dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM comments WHERE article_id = ? ORDER BY id DESC LIMIT 50", (article_id,))
            return [dict(r) for r in cur.fetchall()]

    def add_comment(self, article_id: int, author_name: str, content: str) -> None:
        """Store comment intentionally unfiltered to act as a Stored XSS decoy."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO comments (article_id, author_name, content, likes, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    article_id,
                    (author_name.strip() or "匿名ユーザー")[:60],
                    content[:1000],
                    1,
                    datetime.now(timezone.utc).strftime("%m/%d %H:%M"),
                ),
            )
            self.conn.commit()

    def add_article(self, title: str, category: str, media_name: str, body: str) -> int:
        cat = category if category in CATEGORIES and category != "top" else "it"
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO articles (title, category, media_name, published_at, views, is_pickup, badge, summary, body)
                VALUES (?, ?, ?, ?, 1, 1, '新着', ?, ?)
                """,
                (
                    (title.strip() or "無題のニュース")[:120],
                    cat,
                    (media_name.strip() or "ユーザー投稿")[:40],
                    datetime.now(timezone.utc).strftime("%m/%d(%a) %H:%M"),
                    body.strip()[:120] or "本文なし",
                    body.strip()[:3000] or "本文なし",
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid or 109)

    def vulnerable_search(self, raw_query: str) -> tuple[list[dict[str, Any]], str | None, str]:
        """Intentionally vulnerable string-concatenated SELECT on SQLite."""
        sql = (
            "SELECT id, title, category, media_name, published_at, summary "
            f"FROM articles WHERE title LIKE '%{raw_query}%' OR summary LIKE '%{raw_query}%' ORDER BY id DESC"
        )
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(sql)
                rows = [dict(r) for r in cur.fetchall()]
                return rows, None, sql
            except sqlite3.Error as exc:
                return [], f"sqlite3.OperationalError: {exc} | SQL: {sql}", sql

    def vulnerable_login(self, username: str, password: str) -> tuple[dict[str, Any] | None, str | None, str]:
        """Intentionally vulnerable string-concatenated login query on SQLite."""
        sql = f"SELECT id, username, role, email FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1"
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(sql)
                row = cur.fetchone()
                return (dict(row) if row else None), None, sql
            except sqlite3.Error as exc:
                return None, f"sqlite3.OperationalError: {exc} | SQL: {sql}", sql

    def get_user_by_id_idor(self, user_id_raw: str) -> tuple[list[dict[str, Any]], str | None]:
        """Intentionally vulnerable IDOR + SQLi endpoint returning user records."""
        sql = f"SELECT id, username, role, email, api_token, internal_note FROM users WHERE id = {user_id_raw}"
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(sql)
                return [dict(r) for r in cur.fetchall()], None
            except sqlite3.Error as exc:
                return [], f"sqlite3.OperationalError: {exc}"


class HoneypotState:
    """Thread-safe state combining SQLite news store and security telemetry."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started_at = utc_now_iso()
        self.events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.path_hits: Counter[str] = Counter()
        self.ip_hits: Counter[str] = Counter()
        self.url_hits: Counter[str] = Counter()
        self.technique_hits: Counter[str] = Counter()
        self.failed_logins_by_ip: defaultdict[str, int] = defaultdict(int)
        self.fingerprinter = HttpFingerprinter()
        self.threat_intel_engine = ThreatIntelEngine()
        self.emulator = VirtualAttackEmulator()
        self.db = NewsSQLiteStore(os.environ.get("HONEYPOT_DB_PATH", "/tmp/portal_news.db"))
        self.sessions: dict[str, dict[str, Any]] = {}

        self.device_config: dict[str, Any] = {
            "device_model": "DecoyGateway-X200",
            "firmware_version": "v3.8.2-sim",
            "hostname": "news-edge-gw-01",
            "wan": {"mode": "dhcp", "ip_address": "198.51.100.10", "gateway": "198.51.100.1"},
            "lan": {"ip_address": "192.168.10.1", "subnet_mask": "255.255.255.0", "dhcp_enabled": True},
        }
        self.dotenv_decoy = self.emulator.laravel_env_decoy
        self.config_json_decoy: dict[str, Any] = {
            "service": "yaho-news-portal",
            "environment": "production",
            "db_path": self.db.db_path,
            "endpoints": {
                "news": "/",
                "search": "/search?q=",
                "user_profile_idor": "/api/v1/users/profile?id=1",
                "ssrf_preview": "/api/v1/fetch?url=",
                "download_lfi": "/download?file=",
            },
        }

    def record_event(self, event: dict[str, Any]) -> None:
        enriched = {"timestamp": utc_now_iso(), **event}
        intel = enriched.get("threat_intel") or {}
        urls = intel.get("captured_attacker_urls") or []
        techs = intel.get("attack_techniques") or []

        with self.lock:
            self.events.append(enriched)
            self.path_hits[str(enriched.get("path", ""))] += 1
            self.ip_hits[str(enriched.get("client_ip", "unknown"))] += 1
            for u in urls:
                self.url_hits[str(u)] += 1
            for t in techs:
                self.technique_hits[str(t)] += 1

        print(json.dumps(enriched, ensure_ascii=True), flush=True)

    def create_session(self, username: str, role: str) -> str:
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = {"username": username, "role": role, "created_at": utc_now_iso()}
        return token

    def get_session(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        with self.lock:
            return self.sessions.get(token)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "status": "ok",
                "started_at": self.started_at,
                "sqlite_db": self.db.db_path,
                "total_events": len(self.events),
                "unique_ips": len(self.ip_hits),
                "top_paths": self.path_hits.most_common(15),
                "top_ips": self.ip_hits.most_common(10),
                "top_captured_urls": self.url_hits.most_common(20),
                "attack_techniques_breakdown": dict(self.technique_hits.most_common()),
                "failed_login_ips": dict(self.failed_logins_by_ip),
                "active_sessions": len(self.sessions),
            }


def render_portal_page(
    page_title: str,
    main_html: str,
    ranking: list[dict[str, Any]],
    active_cat: str = "top",
    session_user: str | None = None,
    search_query: str = "",
) -> bytes:
    """Render a Japanese portal-style layout (Yahoo! News inspired)."""
    tabs_html = "".join(
        f"<a class='tab {'active' if active_cat == cid else ''}' href='/?cat={cid}'>{html.escape(cname)}</a>"
        for cid, cname in CATEGORIES.items()
    )

    rank_html = "".join(
        f"<li class='rank-item'><span class='rank-num r{idx}'>{idx}</span>"
        f"<a href='/articles/{r['id']}'>{html.escape(str(r['title']))}</a>"
        f"<div class='rank-meta'>{html.escape(str(r['media_name']))} ・ {int(r['views']):,} PV</div></li>"
        for idx, r in enumerate(ranking, start=1)
    )

    user_box = (
        f"<div class='side-card'><h3>ログイン中</h3><p>ようこそ <strong>{html.escape(session_user)}</strong> さん</p>"
        "<p style='font-size:12px;'><a href='/admin'>編成管理画面</a> | <a href='/api/v1/users/profile?id=1'>会員情報API</a> | <a href='/logout'>ログアウト</a></p></div>"
        if session_user
        else (
            "<div class='side-card'><h3>ニュースID ログイン</h3>"
            "<form method='POST' action='/login'>"
            "<input type='text' name='username' placeholder='ID / ユーザー名' style='margin-bottom:6px;'>"
            "<input type='password' name='password' placeholder='パスワード' style='margin-bottom:8px;'>"
            "<button type='submit' class='btn-primary' style='width:100%;'>ログイン</button>"
            "</form><div style='margin-top:6px;font-size:11px;color:#666;'>"
            "<a href='/posts/new'>記事投稿</a> ・ <a href='/admin'>管理画面</a></div></div>"
        )
    )

    doc = f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(page_title)} - Yaho! ニュース</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Hiragino Kaku Gothic ProN", "Yu Gothic", Meiryo, sans-serif; background: #f2f4f7; color: #222; font-size: 14px; }}
    a {{ color: #1a56db; text-decoration: none; }}
    a:hover {{ text-decoration: underline; color: #d91c1c; }}
    .top-bar {{ background: #ffffff; border-bottom: 1px solid #e2e6ec; }}
    .top-inner {{ max-width: 1080px; margin: 0 auto; padding: 10px 14px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; }}
    .brand {{ display: flex; align-items: baseline; gap: 6px; }}
    .brand-logo {{ font-size: 24px; font-weight: 900; color: #ff0033; letter-spacing: -0.5px; }}
    .brand-sub {{ font-size: 16px; font-weight: 700; color: #111; }}
    .search-box {{ display: flex; gap: 4px; flex: 1; max-width: 440px; }}
    .search-box input {{ flex: 1; padding: 7px 10px; border: 2px solid #ff0033; border-radius: 4px; font-size: 13px; }}
    .search-box button {{ background: #ff0033; color: #fff; border: none; border-radius: 4px; padding: 0 14px; font-weight: bold; cursor: pointer; }}
    .nav-strip {{ background: #ffffff; border-bottom: 2px solid #ff0033; }}
    .nav-inner {{ max-width: 1080px; margin: 0 auto; padding: 0 14px; display: flex; overflow-x: auto; }}
    .tab {{ padding: 10px 16px; font-weight: bold; color: #333; white-space: nowrap; border-bottom: 3px solid transparent; }}
    .tab:hover {{ text-decoration: none; background: #fff5f5; color: #ff0033; }}
    .tab.active {{ color: #ff0033; border-bottom-color: #ff0033; }}
    .container {{ max-width: 1080px; margin: 14px auto; padding: 0 14px; display: grid; grid-template-columns: 1fr 310px; gap: 16px; }}
    @media (max-width: 820px) {{ .container {{ grid-template-columns: 1fr; }} }}
    .main-card, .side-card {{ background: #ffffff; border: 1px solid #dfe3e8; border-radius: 6px; padding: 14px 16px; margin-bottom: 14px; }}
    .side-card h3 {{ margin: 0 0 10px 0; font-size: 14px; border-left: 4px solid #ff0033; padding-left: 8px; }}
    .pickup-wrap {{ display: grid; grid-template-columns: 1fr 220px; gap: 14px; align-items: start; }}
    @media (max-width: 640px) {{ .pickup-wrap {{ grid-template-columns: 1fr; }} }}
    .topic-list {{ list-style: none; margin: 0; padding: 0; }}
    .topic-list li {{ padding: 8px 4px; border-bottom: 1px solid #eef0f3; display: flex; align-items: center; gap: 6px; }}
    .topic-list li a {{ color: #111; font-weight: 600; font-size: 14px; }}
    .topic-list li a:hover {{ color: #ff0033; }}
    .badge {{ background: #ff0033; color: #fff; font-size: 10px; font-weight: bold; padding: 2px 5px; border-radius: 3px; white-space: nowrap; }}
    .thumb-box {{ background: linear-gradient(135deg, #1e3a8a, #2563eb); color: #fff; border-radius: 6px; padding: 12px; min-height: 165px; display: flex; flex-direction: column; justify-content: space-between; }}
    .thumb-box .tag {{ font-size: 11px; background: rgba(255,255,255,0.2); padding: 2px 6px; border-radius: 3px; align-self: flex-start; }}
    .thumb-box .cap {{ font-size: 13px; font-weight: bold; line-height: 1.4; }}
    .feed-item {{ padding: 12px 0; border-bottom: 1px solid #eef0f3; }}
    .feed-title {{ font-size: 16px; font-weight: bold; color: #1a56db; }}
    .feed-meta {{ font-size: 12px; color: #666; margin-top: 4px; }}
    .rank-list {{ list-style: none; margin: 0; padding: 0; }}
    .rank-item {{ padding: 8px 0; border-bottom: 1px solid #eef0f3; }}
    .rank-num {{ display: inline-block; width: 20px; height: 20px; line-height: 20px; text-align: center; border-radius: 3px; background: #94a3b8; color: #fff; font-size: 12px; font-weight: bold; margin-right: 6px; }}
    .rank-num.r1 {{ background: #d97706; }}
    .rank-num.r2 {{ background: #64748b; }}
    .rank-num.r3 {{ background: #b45309; }}
    .rank-meta {{ font-size: 11px; color: #666; margin-left: 26px; margin-top: 2px; }}
    input, select, textarea {{ width: 100%; padding: 7px 9px; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 13px; }}
    .btn-primary {{ background: #1a56db; color: #fff; border: none; border-radius: 4px; padding: 7px 14px; font-weight: bold; cursor: pointer; }}
    .alert-err {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 10px; border-radius: 4px; margin-bottom: 10px; font-family: monospace; font-size: 12px; }}
    .alert-info {{ background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af; padding: 10px; border-radius: 4px; margin-bottom: 10px; }}
    pre {{ background: #0f172a; color: #f8fafc; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
    footer {{ max-width: 1080px; margin: 20px auto 30px; padding: 12px 14px; border-top: 1px solid #dfe3e8; font-size: 12px; color: #666; }}
    footer a {{ color: #475569; margin-right: 10px; }}
  </style>
</head>
<body>
  <div class="top-bar">
    <div class="top-inner">
      <div class="brand">
        <a href="/" style="text-decoration:none;"><span class="brand-logo">YAHO!</span> <span class="brand-sub">ニュース</span></a>
        <span style="font-size:11px;color:#666;margin-left:8px;">{html.escape(display_time_str())}</span>
      </div>
      <form class="search-box" method="GET" action="/search">
        <input type="text" name="q" value="{html.escape(search_query)}" placeholder="キーワード・ニュース検索">
        <button type="submit">検索</button>
      </form>
      <div style="font-size:12px;">
        <a href="/posts/new">記事投稿</a> ・ <a href="/iot/admin">配信設備管理</a> ・ <a href="/admin">管理画面</a>
      </div>
    </div>
  </div>
  <div class="nav-strip">
    <div class="nav-inner">{tabs_html}</div>
  </div>
  <div class="container">
    <main>{main_html}</main>
    <aside>
      {user_box}
      <div class="side-card">
        <h3>アクセスランキング</h3>
        <ol class="rank-list">{rank_html}</ol>
      </div>
      <div class="side-card">
        <h3>天気・マーケット情報</h3>
        <div style="font-size:12px;line-height:1.7;">
          <div><strong>東京</strong>：晴れ 14℃ / 6℃（降水 10%）</div>
          <div><strong>兵庫（神戸）</strong>：晴時々曇 15℃ / 7℃（降水 20%）</div>
          <hr style="border:none;border-top:1px solid #eee;margin:6px 0;">
          <div><strong>日経平均</strong>：38,940.25 <span style="color:#d91c1c;">+215.40</span></div>
          <div><strong>米ドル/円</strong>：154.72 - 154.75</div>
        </div>
      </div>
      <div class="side-card">
        <h3>システム・API連携</h3>
        <div style="font-size:12px;line-height:1.8;">
          <div>・<a href="/download?file=press_release_202611.pdf">プレスリリース資料DL</a></div>
          <div>・<a href="/api/v1/fetch?url=http://127.0.0.1:8080/api/v1/status">外部RSSプレビューAPI</a></div>
          <div>・<a href="/api/v1/tools/ping?host=127.0.0.1">配信ノード疎通確認</a></div>
        </div>
      </div>
    </aside>
  </div>
  <footer>
    <a href="/robots.txt">robots.txt</a>
    <a href="/sitemap.xml">sitemap.xml</a>
    <a href="/feed.xml">RSS</a>
    <a href="/api/v1/status">APIステータス</a>
    <a href="/api/v1/users/profile?id=1">会員API</a>
    <a href="/wp-login.php">CMSログイン</a>
    <a href="/.env">.env</a>
    <a href="/config.json">config.json</a>
    <div style="margin-top:6px;">Copyright (C) 2026 Yaho! News Portal Editorial System. All Rights Reserved.</div>
  </footer>
</body>
</html>"""
    return doc.encode("utf-8")


class HoneypotHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Yaho! News-style SQLite honeypot."""

    state: HoneypotState
    server_version = "PortalHTTP/2.4"
    sys_version = ""

    def version_string(self) -> str:
        """Return only server_version without Python runtime details."""
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _client_ip(self) -> str:
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

    def _tls_info(self) -> dict[str, Any]:
        return {
            "scheme": self.headers.get("X-Forwarded-Proto") or "http",
            "src_port": self.headers.get("X-Real-Port") or "",
            "original_port": self.headers.get("X-Original-Port") or self.headers.get("X-Forwarded-Port") or "",
            "ssl_protocol": self.headers.get("X-SSL-Protocol") or "",
            "ssl_cipher": self.headers.get("X-SSL-Cipher") or "",
            "ssl_server_name": self.headers.get("X-SSL-Server-Name") or "",
        }

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
        if length < 0 or length > 524288:
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
                return {"_malformed_json": text[:4000]}
        qs = parse_qs(text, keep_blank_values=True)
        out: dict[str, Any] = {}
        for k, v in qs.items():
            out[k] = v[0] if len(v) == 1 else v
        if not out and text.strip():
            out["_raw_body"] = text[:4000]
        return out

    def _summarize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for k, v in list(payload.items())[:30]:
            key = str(k)[:100]
            if any(word in key.lower() for word in ("pass", "secret", "token", "key", "pwd")):
                val = str(v)
                summary[key] = {
                    "redacted": True,
                    "length": len(val),
                    "sha256_prefix": sha256_short(val, 8),
                }
            else:
                summary[key] = str(v)[:4000]
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
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if allow_body and self.command != "HEAD":
            self.wfile.write(body)

    def _send_portal(
        self,
        status_code: int,
        page_title: str,
        main_html: str,
        active_cat: str = "top",
        session_user: str | None = None,
        search_query: str = "",
        headers: dict[str, str] | None = None,
        allow_body: bool = True,
    ) -> None:
        ranking = self.state.db.ranking_articles(5)
        raw = render_portal_page(
            page_title=page_title,
            main_html=main_html,
            ranking=ranking,
            active_cat=active_cat,
            session_user=session_user,
            search_query=search_query,
        )
        self._send_raw(status_code, "text/html; charset=utf-8", raw, headers=headers, allow_body=allow_body)

    def _send_json(
        self,
        status_code: int,
        data: dict[str, Any],
        headers: dict[str, str] | None = None,
        allow_body: bool = True,
    ) -> None:
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
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
        raw_headers_list = list(self.headers.items())
        tls_meta = self._tls_info()
        fp_data = self.state.fingerprinter.fingerprint(
            client_ip=client_ip,
            method=self.command,
            path=parsed.path,
            raw_headers=raw_headers_list,
            arrival_monotonic=time.monotonic(),
        )
        intel_data = self.state.threat_intel_engine.analyze(
            client_ip=client_ip,
            user_agent=ua,
            raw_path=self.path,
            raw_query=parsed.query,
            raw_headers=raw_headers_list,
            payload_dict=payload_dict or {},
        )
        effective_outcome = "stage2_url_captured" if intel_data.get("captured_attacker_urls") else outcome

        self.state.record_event(
            {
                "event_type": "http_request",
                "client_ip": client_ip,
                "method": self.command,
                "path": parsed.path,
                "query": parsed.query[:1000],
                "status_code": status_code,
                "outcome": effective_outcome,
                "user_agent": ua[:400],
                "session_user": sess["username"] if sess else None,
                "tls_info": tls_meta,
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
        self._send_json(
            405,
            {"error": "Method Not Allowed", "allowed": ["GET", "HEAD", "POST", "PUT"]},
            {"Allow": "GET, HEAD, POST, PUT"},
        )
        self._log_event(405, "method_not_allowed")

    def _combined_probe_text(self, parsed_path: str, parsed_query: str, payload: dict[str, Any]) -> str:
        header_vals = " ".join(f"{k}:{v}" for k, v in self.headers.items())
        body_vals = " ".join(f"{k}={v}" for k, v in payload.items())
        return unquote(f"{parsed_path} {parsed_query} {header_vals} {body_vals}")

    def _dispatch(self, allow_body: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        qs = parse_qs(parsed.query, keep_blank_values=True)
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
        probe_text = self._combined_probe_text(self.path, parsed.query, payload)

        # --- 0. Framework & RCE / Traversal Decoys ---
        if "phpunit" in path.lower() and path.lower().endswith("eval-stdin.php"):
            token = extract_echo_token(probe_text) or "PHPUNIT_SIM_OK"
            self._send_raw(200, "text/plain; charset=utf-8", f"<?xml version='1.0'?>\n{token}\n".encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "decoy_phpunit_eval_bait", payload, payload_summary)
            return

        if path.startswith("/cgi-bin/") or "etc/passwd" in unquote(self.path).lower() or "%2e%2e" in self.path.lower():
            token = extract_echo_token(probe_text)
            body = f"{self.state.emulator.passwd_decoy}\n{token}\n" if token else f"{self.state.emulator.passwd_decoy}\n"
            self._send_raw(200, "text/plain; charset=utf-8", body.encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "decoy_traversal_passwd_bait", payload, payload_summary)
            return

        if "think\\app" in unquote(self.path).lower() or "invokefunction" in probe_text.lower():
            token = extract_echo_token(probe_text) or "THINKPHP_SIM_READY"
            self._send_raw(200, "text/plain; charset=utf-8", f"{token}\n".encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "decoy_thinkphp_rce_bait", payload, payload_summary)
            return

        # --- 1. Yaho! News-style Top / Category Portal ---
        if path in {"/", "/news", "/blog", "/posts/list"}:
            if self.command in {"POST", "PUT"}:
                tok = extract_echo_token(probe_text) or "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                resp_body = f'0:["$@1",["development",null]]\n1:{{"status":"ok","output":{json.dumps(tok)}}}\n'.encode("utf-8")
                self._send_raw(
                    200,
                    "text/x-component; charset=utf-8",
                    resp_body,
                    headers={"X-Action-Rebound": "1"},
                    allow_body=allow_body,
                )
                self._log_event(200, "next_action_rce_bait", payload, payload_summary)
                return

            cat = (qs.get("cat", ["top"])[0] or "top").lower()
            if cat not in CATEGORIES:
                cat = "top"
            articles = self.state.db.list_articles(category=cat, limit=15)
            top_topics = articles[:8]
            lead = top_topics[0] if top_topics else None

            topics_li = "".join(
                f"<li><a href='/articles/{a['id']}'>{html.escape(str(a['title']))}</a>"
                + (f"<span class='badge'>{html.escape(str(a['badge']))}</span>" if a.get("badge") else "")
                + "</li>"
                for a in top_topics
            )
            thumb_html = (
                f"<a href='/articles/{lead['id']}' style='text-decoration:none;'>"
                f"<div class='thumb-box'><span class='tag'>{html.escape(CATEGORIES.get(lead['category'], '主要'))} TOP</span>"
                f"<div class='cap'>{html.escape(str(lead['title']))}</div>"
                f"<div style='font-size:11px;opacity:0.85;'>{html.escape(str(lead['media_name']))}</div></div></a>"
                if lead
                else ""
            )

            feed_html = "".join(
                f"<div class='feed-item'>"
                f"<a class='feed-title' href='/articles/{a['id']}'>{html.escape(str(a['title']))}</a>"
                f"<p style='margin:6px 0;color:#444;line-height:1.5;'>{html.escape(str(a['summary']))}</p>"
                f"<div class='feed-meta'>{html.escape(str(a['media_name']))} ・ {html.escape(str(a['published_at']))} ・ {int(a['views']):,} PV</div>"
                f"</div>"
                for a in articles
            )

            main_html = (
                f"<div class='main-card'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;'>"
                f"<strong style='font-size:15px;'>{html.escape(CATEGORIES[cat])}トピックス</strong>"
                f"<span style='font-size:11px;color:#666;'>SQLite 配信中</span></div>"
                f"<div class='pickup-wrap'><ul class='topic-list'>{topics_li}</ul>{thumb_html}</div>"
                f"</div>"
                f"<div class='main-card'><strong style='font-size:15px;'>最新ニュース一覧</strong>{feed_html}</div>"
            )
            self._send_portal(200, f"{CATEGORIES[cat]}ニュース", main_html, active_cat=cat, session_user=session_user, allow_body=allow_body)
            self._log_event(200, "news_portal_top", payload, {"category": cat})
            return

        # --- 2. Vulnerable Search (SQLite SQLi + Reflected XSS Decoy) ---
        if path == "/search":
            q_raw = qs.get("q", [""])[0]
            rows, sql_err, executed_sql = self.state.db.vulnerable_search(q_raw)

            # Intentional Reflected XSS: q_raw rendered directly without escaping
            banner = f"<div class='alert-info'>検索キーワード: <strong>{q_raw}</strong>（ヒット件数: {len(rows)}件）</div>"
            err_box = f"<div class='alert-err'>{html.escape(sql_err)}</div>" if sql_err else ""
            items_html = "".join(
                f"<div class='feed-item'>"
                f"<a class='feed-title' href='/articles/{r.get('id', 101)}'>{html.escape(str(r.get('title', '')))}</a>"
                f"<p style='margin:5px 0;color:#444;'>{html.escape(str(r.get('summary', '')))}</p>"
                f"<div class='feed-meta'>{html.escape(str(r.get('media_name', '')))} ・ {html.escape(str(r.get('published_at', '')))}</div>"
                f"</div>"
                for r in rows
            ) or "<p>該当する記事は見つかりませんでした。</p>"

            main_html = f"<div class='main-card'><h2 style='margin-top:0;font-size:17px;'>記事検索結果</h2>{banner}{err_box}{items_html}</div>"
            status = 500 if sql_err else 200
            self._send_portal(status, "検索結果", main_html, session_user=session_user, search_query=q_raw, allow_body=allow_body)
            self._log_event(status, "sqli_xss_search_probe" if (sql_err or "<" in q_raw) else "news_search", payload, {"q": q_raw, "sql": executed_sql})
            return

        # --- 3. Article Detail + Stored XSS Comment Form ---
        if path.startswith("/articles/"):
            sub = path.split("/articles/", 1)[1].strip("/")
            parts = sub.split("/")
            try:
                art_id = int(parts[0])
            except ValueError:
                self._send_portal(400, "不正な記事ID", "<div class='main-card'><p>記事IDが不正です。</p></div>", session_user=session_user, allow_body=allow_body)
                self._log_event(400, "invalid_article_id", payload, {"raw_id": sub})
                return

            if len(parts) == 2 and parts[1] == "comment" and self.command == "POST":
                author = str(payload.get("author_name", "匿名ユーザー"))
                content = str(payload.get("content", ""))
                if content.strip():
                    self.state.db.add_comment(art_id, author, content)
                self._send_raw(
                    302,
                    "text/plain; charset=utf-8",
                    b"Redirecting...",
                    headers={"Location": f"/articles/{art_id}"},
                    allow_body=allow_body,
                )
                self._log_event(302, "stored_xss_comment_post", payload, payload_summary)
                return

            art = self.state.db.get_article(art_id)
            if not art:
                self._send_portal(404, "記事が見つかりません", "<div class='main-card'><p>指定された記事は削除されたか存在しません。</p></div>", session_user=session_user, allow_body=allow_body)
                self._log_event(404, "article_not_found", payload, {"article_id": art_id})
                return

            comments = self.state.db.get_comments(art_id)
            # Intentional Stored XSS: comment author_name and content rendered raw
            comments_html = "".join(
                f"<div style='padding:10px 0;border-bottom:1px solid #eef0f3;'>"
                f"<div style='font-size:12px;font-weight:bold;color:#333;'>{c['author_name']} "
                f"<span style='font-weight:normal;color:#777;margin-left:6px;'>{html.escape(str(c['created_at']))}</span></div>"
                f"<div style='margin-top:4px;line-height:1.5;'>{c['content']}</div></div>"
                for c in comments
            ) or "<p style='color:#666;'>まだコメントはありません。</p>"

            main_html = (
                f"<div class='main-card'>"
                f"<div style='font-size:12px;color:#666;'>{html.escape(str(art['media_name']))} ・ {html.escape(str(art['published_at']))} 配信</div>"
                f"<h1 style='font-size:21px;margin:8px 0 14px;line-height:1.4;'>{html.escape(str(art['title']))}</h1>"
                f"<p style='line-height:1.8;font-size:15px;'>{html.escape(str(art['body']))}</p>"
                f"</div>"
                f"<div class='main-card'>"
                f"<h3 style='margin-top:0;font-size:15px;'>みんなの意見・コメント（{len(comments)}件）</h3>"
                f"<form method='POST' action='/articles/{art_id}/comment' style='margin-bottom:14px;'>"
                f"<input type='text' name='author_name' placeholder='表示名（任意）' style='margin-bottom:6px;'>"
                f"<textarea name='content' rows='3' placeholder='記事へのコメントを投稿する...' required style='margin-bottom:6px;'></textarea>"
                f"<button type='submit' class='btn-primary'>コメントを投稿</button></form>"
                f"{comments_html}</div>"
            )
            self._send_portal(200, str(art["title"]), main_html, active_cat=str(art["category"]), session_user=session_user, allow_body=allow_body)
            self._log_event(200, "article_detail", payload, {"article_id": art_id})
            return

        # --- 4. Vulnerable Login (SQLite Auth Bypass Decoy) ---
        if path in {"/login", "/wp-login.php", "/boaform/admin/formLogin"}:
            if self.command == "GET":
                form = (
                    f"<div class='main-card'><h2 style='margin-top:0;font-size:17px;'>ログイン（{html.escape(path)}）</h2>"
                    f"<form method='POST' action='{html.escape(path)}'>"
                    "<label>ユーザーID</label><input type='text' name='username' style='margin:6px 0 10px;' required>"
                    "<label>パスワード</label><input type='password' name='password' style='margin:6px 0 12px;' required>"
                    "<button type='submit' class='btn-primary'>ログイン</button></form></div>"
                )
                self._send_portal(200, "ログイン", form, session_user=session_user, allow_body=allow_body)
                self._log_event(200, "login_form", payload, payload_summary)
                return

            if self.command == "POST":
                user = str(payload.get("username") or payload.get("user_login") or payload.get("inputStr") or "")
                pwd = str(payload.get("password") or payload.get("user_pass") or payload.get("inputPwd") or "")
                row, sql_err, executed_sql = self.state.db.vulnerable_login(user, pwd)
                if sql_err:
                    err_html = f"<div class='main-card'><div class='alert-err'>{html.escape(sql_err)}</div></div>"
                    self._send_portal(500, "ログインエラー", err_html, session_user=session_user, allow_body=allow_body)
                    self._log_event(500, "sqli_login_error", payload, payload_summary)
                    return
                if row:
                    token = self.state.create_session(str(row["username"]), str(row["role"]))
                    self._send_raw(
                        302,
                        "text/plain; charset=utf-8",
                        b"Redirecting to admin...",
                        headers={
                            "Location": "/admin",
                            "Set-Cookie": f"portal_session={token}; Path=/",
                        },
                        allow_body=allow_body,
                    )
                    self._log_event(302, "sqli_or_valid_login_success", payload, {"matched_user": row["username"], "sql": executed_sql, **payload_summary})
                    return

                self.state.failed_logins_by_ip[self._client_ip()] += 1
                fail_html = "<div class='main-card'><div class='alert-err'>IDまたはパスワードが正しくありません。</div></div>"
                self._send_portal(401, "認証失敗", fail_html, session_user=session_user, allow_body=allow_body)
                self._log_event(401, "login_failed", payload, payload_summary)
                return

        if path == "/logout":
            self._send_raw(
                302,
                "text/plain; charset=utf-8",
                b"Logged out",
                headers={"Location": "/", "Set-Cookie": "portal_session=; Max-Age=0; Path=/"},
                allow_body=allow_body,
            )
            self._log_event(302, "logout", payload, payload_summary)
            return

        # --- 5. IDOR / SSRF / LFI / Command Injection Vulnerable Endpoints ---
        if path == "/api/v1/users/profile":
            uid_raw = qs.get("id", ["1"])[0]
            users, sql_err = self.state.db.get_user_by_id_idor(uid_raw)
            if sql_err:
                self._send_json(500, {"error": sql_err}, allow_body=allow_body)
                self._log_event(500, "idor_sqli_error", payload, {"id": uid_raw})
                return
            self._send_json(200, {"status": "ok", "users": users}, allow_body=allow_body)
            self._log_event(200, "idor_user_profile_dump", payload, {"id": uid_raw})
            return

        if path == "/download":
            fname = qs.get("file", ["press_release_202611.pdf"])[0]
            lower = unquote(fname).lower()
            if "passwd" in lower or ".." in lower:
                self._send_raw(200, "text/plain; charset=utf-8", (self.state.emulator.passwd_decoy + "\n").encode("utf-8"), allow_body=allow_body)
                self._log_event(200, "lfi_passwd_dump", payload, {"file": fname})
                return
            if ".env" in lower:
                self._send_raw(200, "text/plain; charset=utf-8", (self.state.dotenv_decoy + "\n").encode("utf-8"), allow_body=allow_body)
                self._log_event(200, "lfi_env_dump", payload, {"file": fname})
                return
            if "portal_news.db" in lower or ".db" in lower:
                self._send_raw(200, "application/octet-stream", b"SQLite format 3\x00SIMULATED_DB_DUMP_HEADER", allow_body=allow_body)
                self._log_event(200, "lfi_sqlite_db_dump", payload, {"file": fname})
                return
            self._send_raw(200, "text/plain; charset=utf-8", f"Yaho! News Press Release Document: {fname}\n".encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "download_file", payload, {"file": fname})
            return

        if path == "/api/v1/fetch":
            target_url = qs.get("url", [""])[0]
            if any(k in target_url.lower() for k in ("169.254.169.254", "metadata", "127.0.0.1", "localhost", "10.")):
                self._send_json(
                    200,
                    {"fetched_url": target_url, "status": 200, "body": self.state.emulator.metadata_decoy},
                    allow_body=allow_body,
                )
                self._log_event(200, "ssrf_metadata_bait", payload, {"url": target_url})
                return
            self._send_json(
                200,
                {"fetched_url": target_url, "status": 200, "rss_items": 8, "note": "Simulated upstream fetch"},
                allow_body=allow_body,
            )
            self._log_event(200, "ssrf_fetch_probe", payload, {"url": target_url})
            return

        if path == "/api/v1/tools/ping":
            host_arg = qs.get("host", ["127.0.0.1"])[0]
            tok = extract_echo_token(host_arg)
            extra_out = f"\n{tok}" if tok else ("\nuid=33(www-data) gid=33(www-data)" if any(c in host_arg for c in (";", "|", "`", "$(")) else "")
            out_txt = f"PING {host_arg} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms{extra_out}\n"
            self._send_raw(200, "text/plain; charset=utf-8", out_txt.encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "cmdi_ping_bait", payload, {"host": host_arg})
            return

        # --- 6. Post Creation / Admin / Discovery / Decoy Files ---
        if path == "/posts/new":
            if self.command == "GET":
                form = (
                    "<div class='main-card'><h2 style='margin-top:0;font-size:17px;'>ニュース記事入稿（SQLite保存）</h2>"
                    "<form method='POST' action='/posts/new'>"
                    "<label>見出し</label><input type='text' name='title' style='margin:6px 0 10px;' required>"
                    "<label>カテゴリ</label><select name='category' style='margin:6px 0 10px;'>"
                    "<option value='domestic'>国内</option><option value='world'>国際</option><option value='economy'>経済</option>"
                    "<option value='ent'>エンタメ</option><option value='sports'>スポーツ</option><option value='it'>IT</option><option value='science'>科学</option>"
                    "</select>"
                    "<label>配信社名</label><input type='text' name='media_name' value='特別報道部' style='margin:6px 0 10px;'>"
                    "<label>本文</label><textarea name='body' rows='5' style='margin:6px 0 12px;' required></textarea>"
                    "<button type='submit' class='btn-primary'>配信する</button></form></div>"
                )
                self._send_portal(200, "記事入稿", form, session_user=session_user, allow_body=allow_body)
                self._log_event(200, "new_post_form", payload, payload_summary)
                return
            if self.command == "POST":
                new_id = self.state.db.add_article(
                    str(payload.get("title", "")),
                    str(payload.get("category", "it")),
                    str(payload.get("media_name", session_user or "特別報道部")),
                    str(payload.get("body", "")),
                )
                self._send_raw(
                    302,
                    "text/plain; charset=utf-8",
                    b"Published",
                    headers={"Location": f"/articles/{new_id}"},
                    allow_body=allow_body,
                )
                self._log_event(302, "article_published", payload, {"article_id": new_id, **payload_summary})
                return

        if path in {"/admin", "/admin/dashboard"}:
            snap = self.state.snapshot()
            main_html = (
                "<div class='main-card'><h2 style='margin-top:0;font-size:17px;'>編成デスク管理コンソール</h2>"
                f"<pre>{html.escape(json.dumps(snap, ensure_ascii=False, indent=2))}</pre></div>"
            )
            self._send_portal(200, "管理コンソール", main_html, session_user=session_user, allow_body=allow_body)
            self._log_event(200, "admin_exposed_view", payload, payload_summary)
            return

        if path in {"/iot/admin", "/cgi-bin/luci"}:
            main_html = (
                "<div class='main-card'><h2 style='margin-top:0;font-size:17px;'>ニュース配信エッジゲートウェイ設定</h2>"
                f"<pre>{html.escape(json.dumps(self.state.device_config, indent=2))}</pre></div>"
            )
            self._send_portal(200, "配信設備管理", main_html, session_user=session_user, allow_body=allow_body)
            self._log_event(200, "iot_admin_view", payload, payload_summary)
            return

        if path == "/robots.txt":
            txt = (
                "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/v1/users/profile\n"
                "Disallow: /api/v1/fetch\nDisallow: /api/v1/tools/ping\nDisallow: /download\n"
                "Sitemap: /sitemap.xml\n"
            ).encode("utf-8")
            self._send_raw(200, "text/plain; charset=utf-8", txt, allow_body=allow_body)
            self._log_event(200, "robots_txt", payload, payload_summary)
            return

        if path == "/sitemap.xml":
            arts = self.state.db.list_articles(limit=30)
            locs = ["/", "/search"] + [f"/articles/{a['id']}" for a in arts]
            body_xml = "\n".join(f"  <url><loc>{loc}</loc></url>" for loc in locs)
            xml = f"<?xml version='1.0' encoding='UTF-8'?>\n<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>\n{body_xml}\n</urlset>\n".encode("utf-8")
            self._send_raw(200, "application/xml; charset=utf-8", xml, allow_body=allow_body)
            self._log_event(200, "sitemap_xml", payload, payload_summary)
            return

        if path in {"/feed.xml", "/rss.xml"}:
            arts = self.state.db.list_articles(limit=20)
            items_xml = "\n".join(
                f"  <item><title>{html.escape(str(a['title']))}</title><link>/articles/{a['id']}</link></item>"
                for a in arts
            )
            rss = f"<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel><title>Yaho! News Feed</title>\n{items_xml}\n</channel></rss>".encode("utf-8")
            self._send_raw(200, "application/rss+xml; charset=utf-8", rss, allow_body=allow_body)
            self._log_event(200, "feed_xml", payload, payload_summary)
            return

        if path == "/api/v1/status":
            self._send_json(200, {"status": "ok", "service": "yaho-news-portal", "db": self.state.db.db_path}, allow_body=allow_body)
            self._log_event(200, "api_status", payload, payload_summary)
            return

        if path == "/.env":
            self._send_raw(200, "text/plain; charset=utf-8", self.state.dotenv_decoy.encode("utf-8"), allow_body=allow_body)
            self._log_event(200, "decoy_dotenv", payload, payload_summary)
            return

        if path == "/config.json":
            self._send_json(200, self.state.config_json_decoy, allow_body=allow_body)
            self._log_event(200, "decoy_config_json", payload, payload_summary)
            return

        if path in {"/actuator", "/actuator/env"}:
            self._send_json(200, self.state.emulator.actuator_env_decoy, allow_body=allow_body)
            self._log_event(200, "decoy_actuator", payload, payload_summary)
            return

        self._send_portal(
            404,
            "ページが見つかりません",
            f"<div class='main-card'><p>指定されたURL（<code>{html.escape(path)}</code>）は見つかりませんでした。</p></div>",
            session_user=session_user,
            allow_body=allow_body,
        )
        self._log_event(404, "not_found", payload, payload_summary)


def run_honeypot(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the Yaho! News-style SQLite honeypot server."""
    state = HoneypotState()
    HoneypotHandler.state = state
    httpd = ThreadingHTTPServer((host, port), HoneypotHandler)
    state.record_event(
        {
            "event_type": "server_start",
            "client_ip": host,
            "method": "INIT",
            "path": "/",
            "status_code": 200,
            "outcome": "listening",
            "payload": {"port": port, "sqlite_db": state.db.db_path},
        }
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        state.record_event(
            {
                "event_type": "server_stop",
                "client_ip": host,
                "method": "SHUTDOWN",
                "path": "/",
                "status_code": 200,
                "outcome": "stopped",
                "payload": state.snapshot(),
            }
        )


if __name__ == "__main__":
    run_honeypot(host="0.0.0.0", port=8080)