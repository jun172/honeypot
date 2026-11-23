import hashlib
import http.server
import json
import os
import re
import socket
import threading
from datetime import datetime, timezone
from typing import cast

HP_HOST = os.getenv("HP_HOST", "0.0.0.0")
HP_PORTS_ENV = os.getenv("HP_PORTS", os.getenv("HP_PORT", "8080"))
HP_MODE = os.getenv("HP_MODE", "realistic").strip().lower()  # "realistic" or "simple"
MAX_BODY_READ = int(os.getenv("MAX_BODY_READ", "65536"))
MAX_BODY_LOG = int(os.getenv("MAX_BODY_LOG", "8192"))
MAX_HEADER_VALUE = 2048
MAX_HEADERS_COUNT = 64
MAX_PATH_LEN = 4096
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", "64"))
SOCKET_TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10.0"))
HEARTBEAT_SEC = int(os.getenv("HEARTBEAT_SEC", "60"))

ALLOWED_METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"
}

CRAWLER_UA_TOKENS = (
    "google-lens",
    "googlebot",
    "adsbot-google",
    "apis-google",
    "mediapartners-google",
    "bingbot",
    "yandexbot",
    "duckduckbot",
)

SCANNER_UA_TOKENS = (
    "zgrab",
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
    "curl/",
    "python-requests",
    "go-http-client",
    "censys",
    "shodan",
    "onyphe",
)

CRED_ENV_PATTERNS = re.compile(
    r"(\.env|aws_access_key|secret_key|private_key|id_rsa|passwd|shadow|/proc/self/environ|wp-config\.php)",
    re.IGNORECASE,
)
TRAVERSAL_PATTERNS = re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.IGNORECASE)
CMD_INJECTION_PATTERNS = re.compile(
    r"(;\s*(sh|bash|wget|curl|chmod|rm|cat|uname|id)\b|`[^`]+`|\$\([^)]+\)|/bin/(sh|bash))",
    re.IGNORECASE,
)
IOT_ROUTER_PATHS = (
    "/boaform/",
    "/cgi-bin/",
    "/hnap1",
    "/setup.cgi",
    "/goform/",
    "/stalker_portal",
    "/sdk",
    "/device.rsp",
)

HTML_BODY = (
    b"<!doctype html><html><head><title>Router Management</title></head>"
    b"<body><h1>Device Portal</h1><p>Authentication required.</p></body></html>\n"
)

_conn_sema = threading.Semaphore(MAX_CONNECTIONS)
_log_lock = threading.Lock()


def parse_ports(raw_ports: str) -> list[int]:
    ports: list[int] = []
    for part in raw_ports.split(","):
        s = part.strip()
        if not s:
            continue
        p = int(s)
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    return ports or [8080]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_log(payload: dict) -> None:
    payload.setdefault("ts", utc_now_iso())
    line = json.dumps(payload, ensure_ascii=False)
    with _log_lock:
        print(line, flush=True)


def sanitize_headers(headers_obj) -> dict:
    result = {}
    if headers_obj is None:
        return result
    count = 0
    for k, v in headers_obj.items():
        if count >= MAX_HEADERS_COUNT:
            break
        key_str = str(k)[:256]
        val_str = str(v)[:MAX_HEADER_VALUE]
        result.setdefault(key_str, []).append(val_str)
        count += 1
    return result


def get_first_header(headers_dict: dict, name: str) -> str:
    target = name.lower()
    for k, vals in headers_dict.items():
        if k.lower() == target and vals:
            return str(vals[0])
    return ""


def analyze_request(
    method: str,
    path: str,
    user_agent: str,
    body_text: str,
    body_read_len: int,
    raw_request_line: str = "",
) -> dict:
    ua_lower = user_agent.lower()
    path_lower = path.lower()
    haystack = f"{path}\n{body_text}"

    is_crawler = any(tok in ua_lower for tok in CRAWLER_UA_TOKENS)
    is_scanner_ua = any(tok in ua_lower for tok in SCANNER_UA_TOKENS)
    norm_path = path.split("?", 1)[0]
    is_empty_get_root = (
        method.upper() == "GET"
        and norm_path in ("/", "/favicon.ico")
        and body_read_len == 0
    )
    is_tls_handshake = raw_request_line.startswith("\\u0016\\u0003") or (
        len(raw_request_line) >= 2 and raw_request_line[:2] == "\x16\x03"
    )

    tags: list[str] = []
    score = 0

    if is_tls_handshake:
        tags.append("tls_on_plaintext")
        score += 20
    if is_scanner_ua:
        tags.append("scanner_ua")
        score += 25
    if any(path_lower.startswith(p) for p in IOT_ROUTER_PATHS):
        tags.append("iot_router_path")
        score += 35
    if TRAVERSAL_PATTERNS.search(haystack):
        tags.append("path_traversal")
        score += 45
    if CRED_ENV_PATTERNS.search(haystack):
        tags.append("cred_or_env_probe")
        score += 50
    if CMD_INJECTION_PATTERNS.search(haystack):
        tags.append("cmd_injection_pattern")
        score += 60
    if method.upper() in ("POST", "PUT", "PATCH") and body_read_len > 0:
        tags.append("has_payload")
        score += 15

    score = min(score, 100)

    if is_tls_handshake:
        category = "tls_on_plaintext"
    elif is_crawler:
        category = "crawler"
    elif is_empty_get_root and score == 0:
        category = "benign_probe"
    elif "cmd_injection_pattern" in tags or "cred_or_env_probe" in tags:
        category = "high_interest_attack"
    else:
        category = "http_probe"

    return {
        "is_crawler": is_crawler,
        "is_empty_get_root": is_empty_get_root,
        "traffic_category": category,
        "attack_tags": tags,
        "suspicion_score": score,
    }


def read_request_body(rfile, headers) -> tuple[bytes, int | None, str | None]:
    te_hdr = (headers.get("Transfer-Encoding") or "").lower()
    cl_hdr = headers.get("Content-Length")

    if "chunked" in te_hdr:
        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                line = rfile.readline(128)
                if not line:
                    return b"".join(chunks), None, "chunked_unexpected_eof"
                hex_part = line.split(b";", 1)[0].strip()
                chunk_size = int(hex_part, 16)
                if chunk_size == 0:
                    rfile.readline(128)
                    break
                to_read = min(chunk_size, MAX_BODY_READ - total)
                if to_read > 0:
                    data = rfile.read(to_read)
                    chunks.append(data)
                    total += len(data)
                # 残りチャンク分と末尾CRLFを消費してストリームを揃える
                rem_discard = max(0, chunk_size - max(0, to_read)) + 2
                while rem_discard > 0:
                    skip = rfile.read(min(rem_discard, 4096))
                    if not skip:
                        break
                    rem_discard -= len(skip)
                if total >= MAX_BODY_READ:
                    return b"".join(chunks), None, "body_truncated_max_read"
        except Exception as exc:
            return b"".join(chunks), None, f"chunked_error:{type(exc).__name__}"
        return b"".join(chunks), None, None

    if cl_hdr is not None:
        try:
            declared_len = int(cl_hdr.strip())
            if declared_len < 0:
                declared_len = 0
        except ValueError:
            return b"", 0, "invalid_content_length"

        if declared_len == 0:
            return b"", 0, None

        to_read = min(declared_len, MAX_BODY_READ)
        chunks = []
        remaining = to_read
        read_err = None
        while remaining > 0:
            try:
                chunk = rfile.read(remaining)
            except Exception as exc:
                read_err = f"read_error:{type(exc).__name__}"
                break
            if not chunk:
                read_err = read_err or "unexpected_eof"
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), declared_len, read_err

    return b"", None, None


class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "nginx/1.24.0"
    sys_version = ""

    def setup(self):
        self.request.settimeout(SOCKET_TIMEOUT)
        super().setup()

    def log_message(self, format, *args):
        return

    def _client_addr(self) -> tuple[str, int]:
        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple) and len(addr) >= 2:
            return str(addr[0]), int(addr[1])
        return "0.0.0.0", 0

    def _dst_port(self) -> int:
        srv_addr = getattr(self.server, "server_address", None)
        if isinstance(srv_addr, tuple) and len(srv_addr) >= 2:
            return int(srv_addr[1])
        return 0

    def _send_response_bytes(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        try:
            self.send_response(code)
            self.send_header("Server", self.server_version)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            pass

    def _send_decoy_response(self, path: str) -> None:
        if HP_MODE == "simple":
            body = b"" if self.command == "HEAD" else HTML_BODY
            self._send_response_bytes(200, body)
            return

        p_lower = path.lower()
        if any(tok in p_lower for tok in (".env", "wp-config", ".git")):
            self._send_response_bytes(404, b"Not Found\n", "text/plain; charset=utf-8")
        elif any(tok in p_lower for tok in ("admin", "login", "manager", "console")):
            self._send_response_bytes(401, b"Unauthorized\n", "text/plain; charset=utf-8")
        else:
            body = b"" if self.command == "HEAD" else HTML_BODY
            self._send_response_bytes(200, body)

    def parse_request(self) -> bool:
        src_ip, src_port = self._client_addr()
        dst_port = self._dst_port()
        raw_line = getattr(self, "raw_requestline", b"") or b""
        raw_ascii = raw_line[:300].decode("ascii", errors="replace")

        ok = super().parse_request()
        headers_clean = sanitize_headers(getattr(self, "headers", None))
        ua = get_first_header(headers_clean, "User-Agent")

        if not ok:
            analysis = analyze_request("", "", ua, "", 0, raw_ascii)
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "code": 400,
                "raw_request_line": raw_ascii,
                "headers": headers_clean,
                **analysis,
            })
            return False

        method = getattr(self, "command", "")
        if method not in ALLOWED_METHODS:
            analysis = analyze_request(
                method, getattr(self, "path", "") or "", ua, "", 0, raw_ascii
            )
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "code": 501,
                "raw_request_line": raw_ascii,
                "headers": headers_clean,
                **analysis,
            })
            self._send_response_bytes(501, b"Not Implemented\n", "text/plain; charset=utf-8")
            return False

        return True

    def _handle_any(self) -> None:
        src_ip, src_port = self._client_addr()
        dst_port = self._dst_port()
        raw_path = getattr(self, "path", "") or ""
        path = raw_path[:MAX_PATH_LEN]

        read_bytes, declared_len, read_error = read_request_body(self.rfile, self.headers)
        headers_clean = sanitize_headers(self.headers)
        ua = get_first_header(headers_clean, "User-Agent")
        xff = get_first_header(headers_clean, "X-Forwarded-For") or None
        forwarded_port = get_first_header(headers_clean, "X-Forwarded-Port") or None

        body_sha256 = hashlib.sha256(read_bytes).hexdigest()
        body_text = read_bytes.decode("utf-8", errors="replace")[:MAX_BODY_LOG]
        analysis = analyze_request(
            method=self.command,
            path=path,
            user_agent=ua,
            body_text=body_text,
            body_read_len=len(read_bytes),
        )

        emit_log({
            "event": "request",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "x_forwarded_for": xff,
            "forwarded_port": forwarded_port,
            "method": self.command,
            "path": path,
            "http_version": self.request_version,
            "headers": headers_clean,
            "body_declared_len": declared_len,
            "body_read_len": len(read_bytes),
            "body_sha256": body_sha256,
            "body": body_text,
            "read_error": read_error,
            **analysis,
        })

        self._send_decoy_response(path)

    def do_GET(self): self._handle_any()
    def do_HEAD(self): self._handle_any()
    def do_POST(self): self._handle_any()
    def do_PUT(self): self._handle_any()
    def do_DELETE(self): self._handle_any()
    def do_PATCH(self): self._handle_any()
    def do_OPTIONS(self): self._handle_any()
    def do_TRACE(self): self._handle_any()
    def do_CONNECT(self): self._handle_any()


class BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _conn_sema.release()

    def process_request(self, request, client_address):
        raw_sock = request[1] if isinstance(request, tuple) and len(request) >= 2 else request
        sock = cast(socket.socket, raw_sock)

        if not _conn_sema.acquire(blocking=False):
            src_ip = client_address[0] if client_address else "0.0.0.0"
            src_port = client_address[1] if client_address and len(client_address) > 1 else 0
            dst_port = self.server_address[1] if isinstance(self.server_address, tuple) else 0
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "code": 503,
                "raw_request_line": "max_connections_exceeded",
                "headers": {},
                "is_crawler": False,
                "is_empty_get_root": False,
                "traffic_category": "http_probe",
                "attack_tags": ["rate_or_conn_limit"],
                "suspicion_score": 10,
            })
            try:
                sock.sendall(b"HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return

        t = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            daemon=True,
        )
        t.start()


def heartbeat_loop(stop_event: threading.Event, ports: list[int]) -> None:
    while not stop_event.wait(HEARTBEAT_SEC):
        emit_log({"event": "heartbeat", "ports": ports})


def main() -> None:
    ports = parse_ports(HP_PORTS_ENV)
    servers: list[BoundedThreadingHTTPServer] = []
    threads: list[threading.Thread] = []

    for p in ports:
        srv = BoundedThreadingHTTPServer((HP_HOST, p), HoneypotHandler)
        servers.append(srv)
        th = threading.Thread(
            target=srv.serve_forever,
            kwargs={"poll_interval": 0.5},
            daemon=True,
        )
        th.start()
        threads.append(th)

    stop_event = threading.Event()
    hb_thread = threading.Thread(
        target=heartbeat_loop,
        args=(stop_event, ports),
        daemon=True,
    )
    hb_thread.start()

    emit_log({"event": "start", "ports": ports, "mode": HP_MODE})
    try:
        while not stop_event.is_set():
            stop_event.wait(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for srv in servers:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    main()