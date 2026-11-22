import hashlib
import http.server
import json
import os
import socket
import threading
from datetime import datetime, timezone
from typing import cast

HP_HOST = os.getenv("HP_HOST", "0.0.0.0")
HP_PORT = int(os.getenv("HP_PORT", "8080"))
MAX_BODY_READ = 65536
MAX_BODY_LOG = 8192
MAX_HEADER_VALUE = 2048
MAX_PATH_LEN = 4096
MAX_CONNECTIONS = 64
SOCKET_TIMEOUT = 10.0
HEARTBEAT_SEC = 60

ALLOWED_METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"
}

HTML_BODY = (
    b"<!doctype html><html><head><title>Welcome</title></head>"
    b"<body><h1>It works!</h1></body></html>\n"
)

_conn_sema = threading.Semaphore(MAX_CONNECTIONS)
_log_lock = threading.Lock()


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
    for k, v in headers_obj.items():
        key_str = str(k)[:256]
        val_str = str(v)[:MAX_HEADER_VALUE]
        result.setdefault(key_str, []).append(val_str)
    return result


class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "nginx"
    sys_version = ""

    def setup(self):
        self.request.settimeout(SOCKET_TIMEOUT)
        super().setup()

    def log_message(self, format, *args):
        # 標準の簡易アクセスログは抑止し、JSONログのみ出力する
        return

    def _client_addr(self):
        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple) and len(addr) >= 2:
            return str(addr[0]), int(addr[1])
        return "0.0.0.0", 0

    def _send_fixed_200(self, include_body: bool) -> None:
        body = HTML_BODY if include_body else b""
        self.send_response(200)
        self.send_header("Server", "nginx")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body and body:
            self.wfile.write(body)

    def _send_error_response(self, code: int) -> None:
        msg = b"Bad Request\n" if code == 400 else b"Method Not Allowed\n"
        try:
            self.send_response(code)
            self.send_header("Server", "nginx")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(msg)
        except Exception:
            pass

    def parse_request(self) -> bool:
        src_ip, src_port = self._client_addr()
        raw_line = getattr(self, "raw_requestline", b"") or b""
        raw_ascii = raw_line[:300].decode("ascii", errors="replace")

        ok = super().parse_request()
        if not ok:
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "code": 400,
                "raw_request_line": raw_ascii,
                "headers": sanitize_headers(getattr(self, "headers", None)),
            })
            return False

        method = getattr(self, "command", "")
        if method not in ALLOWED_METHODS:
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "code": 501,
                "raw_request_line": raw_ascii,
                "headers": sanitize_headers(getattr(self, "headers", None)),
            })
            self._send_error_response(501)
            return False

        return True

    def _handle_any(self) -> None:
        src_ip, src_port = self._client_addr()
        raw_path = getattr(self, "path", "") or ""
        path = raw_path[:MAX_PATH_LEN]

        content_len_hdr = self.headers.get("Content-Length")
        declared_len = None
        read_bytes = b""
        read_error = None

        if content_len_hdr is not None:
            try:
                declared_len = int(content_len_hdr.strip())
                if declared_len < 0:
                    declared_len = 0
            except ValueError:
                read_error = "invalid_content_length"
                declared_len = 0

            if read_error is None and declared_len > 0:
                to_read = min(declared_len, MAX_BODY_READ)
                chunks = []
                remaining = to_read
                while remaining > 0:
                    try:
                        chunk = self.rfile.read(remaining)
                    except Exception as exc:
                        read_error = f"read_error:{type(exc).__name__}"
                        break
                    if not chunk:
                        read_error = read_error or "unexpected_eof"
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                read_bytes = b"".join(chunks)

        body_sha256 = hashlib.sha256(read_bytes).hexdigest()
        body_text = read_bytes.decode("utf-8", errors="replace")[:MAX_BODY_LOG]

        emit_log({
            "event": "request",
            "src_ip": src_ip,
            "src_port": src_port,
            "method": self.command,
            "path": path,
            "http_version": self.request_version,
            "headers": sanitize_headers(self.headers),
            "body_declared_len": declared_len,
            "body_read_len": len(read_bytes),
            "body_sha256": body_sha256,
            "body": body_text,
            "read_error": read_error,
        })

        self._send_fixed_200(include_body=(self.command != "HEAD"))

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
            emit_log({
                "event": "bad_request",
                "src_ip": src_ip,
                "src_port": src_port,
                "code": 503,
                "raw_request_line": "max_connections_exceeded",
                "headers": {},
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


def heartbeat_loop(stop_event: threading.Event) -> None:
    while not stop_event.wait(HEARTBEAT_SEC):
        emit_log({"event": "heartbeat"})


def main() -> None:
    server = BoundedThreadingHTTPServer((HP_HOST, HP_PORT), HoneypotHandler)
    stop_event = threading.Event()
    hb_thread = threading.Thread(target=heartbeat_loop, args=(stop_event,), daemon=True)
    hb_thread.start()

    emit_log({"event": "start", "port": HP_PORT})
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()