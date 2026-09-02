#!/usr/bin/env python3
"""可直接放在现有业务服务器前方的轻量 WAF 反向代理。

推荐先以 ``monitor`` 模式观察，再切换到 ``block``。代理完整保留 HTTP 方法和原始
请求体，将业务请求转发给任意 HTTP/HTTPS 上游，不要求修改业务代码。

示例：

    python -m src.proxy --backend http://127.0.0.1:3000 --port 8081 --mode monitor
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.parser import parse_auto
from src.pipeline import DetectionPipeline
from src.cache import FeatureCache
from src.settings import MODEL_ROOT, RUNTIME_ROOT, ensure_runtime_dirs
from src.scanner_detector import ScannerBehaviorDetector


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

DEFAULT_TRUSTED_PROXY_CIDRS = ("127.0.0.0/8", "::1/128")

BLOCK_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>403 请求已阻断</title><style>body{font-family:system-ui,sans-serif;display:grid;
place-items:center;min-height:100vh;margin:0;background:#071019;color:#edf6fb}.box{padding:38px;
border:1px solid #59313e;border-radius:14px;background:#101f2c;text-align:center}h1{font-size:64px;
margin:0;color:#ff6b6b}p{color:#8297a7}</style></head><body><div class="box"><h1>403</h1>
<h2>请求已被 Web 攻击检测系统阻断</h2><p>如确认是正常请求，请联系系统管理员。</p></div></body></html>"""


@dataclass(frozen=True)
class ProxyConfig:
    """代理运行配置。"""

    backend: str
    mode: str = "monitor"
    fail_policy: str = "closed"
    timeout: float = 30.0
    max_body_bytes: int = 1024 * 1024
    log_file: Path | None = None
    public_origin: str | None = None
    directory_links: tuple[str, ...] = ()
    trusted_proxy_cidrs: tuple[str, ...] = DEFAULT_TRUSTED_PROXY_CIDRS
    # Exact path/location/name triples for fields that are validated by the
    # upstream application (for example an authenticated rich-text editor).
    field_allowlist: tuple[tuple[str, str, str], ...] = ()

    @property
    def backend_parts(self):
        parsed = urlsplit(self.backend)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("backend 必须是 http:// 或 https:// URL")
        return parsed


def resolve_client_chain(
    peer_ip: str,
    forwarded_for: str | None,
    trusted_proxy_cidrs: tuple[str, ...],
) -> tuple[str, str]:
    """Return the effective client and a sanitized X-Forwarded-For chain.

    The chain is consumed from right to left and stops at the first untrusted
    address. Values before that trust boundary are discarded, so a public
    client cannot prepend a spoofed address through an edge proxy.
    """

    try:
        peer = ipaddress.ip_address(peer_ip)
        networks = tuple(
            ipaddress.ip_network(cidr, strict=False)
            for cidr in trusted_proxy_cidrs
        )
    except ValueError:
        return peer_ip, peer_ip

    def is_trusted(address) -> bool:
        return any(address.version == network.version and address in network for network in networks)

    normalized_peer = str(peer)
    if not forwarded_for or not is_trusted(peer):
        return normalized_peer, normalized_peer

    trusted_suffix = [normalized_peer]
    for raw_value in reversed(forwarded_for.split(",")):
        value = raw_value.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return normalized_peer, normalized_peer
        normalized = str(address)
        trusted_suffix.insert(0, normalized)
        if not is_trusted(address):
            return normalized, ", ".join(trusted_suffix)

    return trusted_suffix[0], ", ".join(trusted_suffix)


def parse_field_allowlist(value: str) -> tuple[tuple[str, str, str], ...]:
    """Parse ``/path:location:name`` entries from a comma-separated value."""

    entries: list[tuple[str, str, str]] = []
    valid_locations = {"query", "body", "header", "cookie"}
    for raw_entry in value.split(","):
        raw_entry = raw_entry.strip()
        if not raw_entry:
            continue
        parts = raw_entry.rsplit(":", 2)
        if len(parts) != 3:
            raise ValueError(
                "field-allowlist 必须使用 /path:location:name 格式"
            )
        path, location, name = (part.strip() for part in parts)
        location = location.lower()
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or location not in valid_locations
            or not name
        ):
            raise ValueError(
                "field-allowlist 包含无效路径、字段位置或名称"
            )
        entry = (path, location, name.casefold())
        if entry not in entries:
            entries.append(entry)
    return tuple(entries)


class WAFProxyHandler(BaseHTTPRequestHandler):
    """并发反向代理处理器；配置由 :func:`configure_handler` 注入。"""

    protocol_version = "HTTP/1.1"
    server_version = "WADProxy/1.0"
    pipeline: DetectionPipeline | None = None
    result_cache = FeatureCache(maxsize=10000)
    config: ProxyConfig | None = None
    scanner_detector: ScannerBehaviorDetector | None = None
    log_lock = threading.Lock()
    control_lock = threading.Lock()
    control_mtime_ns: int | None = None

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_PATCH(self):
        self._handle_request("PATCH")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def log_message(self, format: str, *args) -> None:
        """保留精简访问日志，详细记录写 JSONL。"""

        sys.stdout.write("[proxy] %s - %s\n" % (self.address_string(), format % args))

    def _handle_request(self, method: str) -> None:
        assert self.pipeline is not None and self.config is not None
        self._refresh_runtime_control()
        request_id = uuid.uuid4().hex[:16]
        started = time.perf_counter()

        if self.path == "/_wad/health":
            self._write_status()
            self._send_json(200, {
                "status": "ok",
                "mode": self.config.mode,
                "backend": self.config.backend,
                'public_origin': self.config.public_origin,
                'directory_links': list(self.config.directory_links),
                'field_allowlist': [
                    f"{path}:{location}:{name}"
                    for path, location, name in self.config.field_allowlist
                ],
                "models_loaded": True,
                'log_file': str(self.config.log_file) if self.config.log_file else None,
                'log_writable': (
                    self.config.log_file is None
                    or os.access(self.config.log_file.parent, os.W_OK)
                ),
            }, request_id)
            return

        try:
            body = self._read_body()
        except ValueError as exc:
            self.close_connection = True
            self._send_json(400, {"error": str(exc)}, request_id)
            return
        except OverflowError as exc:
            self.close_connection = True
            self._send_json(413, {"error": str(exc)}, request_id)
            return
        except NotImplementedError as exc:
            self.close_connection = True
            self._send_json(501, {"error": str(exc)}, request_id)
            return

        threats: list[dict] = []
        detection_error: str | None = None
        detection_started = time.perf_counter()
        try:
            threats = self._detect_request(method, body)
            if self.scanner_detector is not None:
                client_ip, _ = self._client_chain()
                scanner = self.scanner_detector.observe(
                    client_ip, self.path, self.headers.get("User-Agent", "")
                )
                if scanner.verdict:
                    threats.append({
                        "location": "request_sequence", "name": "scanner_behavior",
                        "confidence": round(min(0.99, 0.55 + scanner.score * 0.07), 6),
                        "layer": "behavior", "rule_hits": list(scanner.signals),
                        "requests_in_window": scanner.requests_in_window,
                        "distinct_paths": scanner.distinct_paths,
                    })
        except Exception as exc:  # 代理故障策略必须覆盖检测器异常。
            detection_error = f"{type(exc).__name__}: {exc}"
        detection_elapsed_ms = (time.perf_counter() - detection_started) * 1000

        if detection_error and self.config.fail_policy == "closed":
            self._write_log(
                method, request_id, threats, started, detection_elapsed_ms,
                "error", detection_error,
            )
            self._send_json(503, {
                "error": "检测服务暂不可用，请稍后重试",
                "request_id": request_id,
            }, request_id)
            return

        if threats and self.config.mode == "block":
            self._write_log(
                method, request_id, threats, started, detection_elapsed_ms,
                "blocked", detection_error,
            )
            payload = BLOCK_HTML.encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-WAD-Request-ID", request_id)
            self.send_header("X-WAD-Verdict", "attack")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)
            return

        outcome = "monitored_attack" if threats else "forwarded"
        try:
            self._forward(method, body, request_id, bool(threats))
            self._write_log(
                method, request_id, threats, started, detection_elapsed_ms,
                outcome, detection_error,
            )
        except Exception as exc:
            self._write_log(
                method, request_id, threats, started, detection_elapsed_ms,
                "backend_error",
                f"{type(exc).__name__}: {exc}",
            )
            self._send_json(502, {
                "error": "上游业务服务器不可用",
                "request_id": request_id,
            }, request_id)

    def _read_body(self) -> bytes:
        assert self.config is not None
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        content_lengths = self.headers.get_all("Content-Length", [])
        if transfer_encodings:
            codings = [
                item.strip().lower()
                for value in transfer_encodings
                for item in value.split(",")
                if item.strip()
            ]
            if content_lengths:
                raise ValueError("Transfer-Encoding 与 Content-Length 不能同时存在")
            if codings != ["chunked"]:
                raise NotImplementedError("仅支持 chunked Transfer-Encoding")
            return self._read_chunked_body()
        if len(content_lengths) > 1:
            raise ValueError("存在重复 Content-Length")
        try:
            length = int(content_lengths[0]) if content_lengths else 0
        except ValueError as exc:
            raise ValueError("Content-Length 不是有效整数") from exc
        if length < 0:
            raise ValueError("Content-Length 不能为负数")
        if length > self.config.max_body_bytes:
            raise OverflowError(
                f"请求体超过 {self.config.max_body_bytes} 字节限制"
            )
        if not length:
            return b""
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("请求体在 Content-Length 之前结束")
        return body

    def _read_chunked_body(self) -> bytes:
        """Decode one RFC 9112 chunked body with strict framing and limits."""

        assert self.config is not None
        chunks: list[bytes] = []
        total = 0
        while True:
            line = self.rfile.readline(8194)
            if not line.endswith(b"\r\n") or len(line) > 8192:
                raise ValueError("chunked 请求的分块长度行无效")
            size_text = line[:-2].split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError("chunked 请求的分块长度无效") from exc
            if size < 0:
                raise ValueError("chunked 请求的分块长度无效")
            if size == 0:
                trailer_bytes = 0
                while True:
                    trailer = self.rfile.readline(8194)
                    trailer_bytes += len(trailer)
                    if not trailer.endswith(b"\r\n") or len(trailer) > 8192:
                        raise ValueError("chunked 请求的尾部字段无效")
                    if trailer == b"\r\n":
                        return b"".join(chunks)
                    if trailer_bytes > 65536:
                        raise ValueError("chunked 请求的尾部字段过大")
            if total + size > self.config.max_body_bytes:
                raise OverflowError(
                    f"请求体超过 {self.config.max_body_bytes} 字节限制"
                )
            chunk = self.rfile.read(size)
            if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                raise ValueError("chunked 请求的分块数据不完整")
            chunks.append(chunk)
            total += size

    def _client_chain(self) -> tuple[str, str]:
        assert self.config is not None
        return resolve_client_chain(
            self.client_address[0],
            self.headers.get("X-Forwarded-For"),
            self.config.trusted_proxy_cidrs,
        )

    def _detect_request(self, method: str, body: bytes) -> list[dict]:
        assert self.pipeline is not None
        header_text = "\r\n".join(f"{key}: {value}" for key, value in self.headers.items())
        body_text = body.decode("utf-8", errors="replace")
        raw_request = f"{method} {self.path} HTTP/1.1\r\n{header_text}\r\n\r\n{body_text}"
        parsed = parse_auto(raw_request)
        threats = []
        request_path = urlsplit(self.path).path
        for param in parsed:
            # 业务目录和路由只用于定位资源，不作为代理层封禁依据。
            # query/body/header/cookie 仍执行完整规则与模型检测。
            if param.location == 'path':
                continue
            if any(
                allowed_path == request_path
                and allowed_location == param.location
                and allowed_name == param.name.casefold()
                for allowed_path, allowed_location, allowed_name
                in self.config.field_allowlist
            ):
                continue
            cache_key = (param.value, param.location, param.name)
            result = self.result_cache.get(cache_key)
            if result is None:
                result = self.pipeline.detect(
                    param.value, param.location, param.name
                )
                self.result_cache.put(cache_key, result)
            if result.verdict == "attack":
                threats.append({
                    "location": param.location,
                    "name": param.name,
                    "confidence": round(result.confidence, 6),
                    "layer": result.layer,
                    "rule_hits": result.rule_hits[:5],
                })
        return threats

    @staticmethod
    def _rewrite_location(
        value: str,
        backend,
        public_host: str,
        public_proto: str,
    ) -> str:
        '''把上游内部绝对跳转地址改写为用户实际访问的代理地址。'''
        if not public_host or backend.netloc not in value:
            return value
        value = value.replace(backend.netloc, public_host)
        parsed = urlsplit(value)
        if parsed.scheme and parsed.scheme not in {'http', 'https'}:
            return value
        proto = public_proto.split(',', 1)[0].strip().lower()
        if proto not in {'http', 'https'}:
            proto = 'http'
        if parsed.netloc == public_host:
            return parsed._replace(scheme=proto).geturl()
        return value

    @staticmethod
    def _rewrite_response_body(
        payload: bytes,
        headers: list[tuple[str, str]],
        backend,
        public_host: str,
        public_proto: str,
        directory_links: tuple[str, ...] = (),
    ) -> tuple[bytes, bool]:
        '''改写文本响应中指向 Docker 内部上游的绝对 URL。'''
        content_encoding = next(
            (v.lower() for k, v in headers if k.lower() == 'content-encoding'), ''
        )
        content_type = next(
            (v.lower() for k, v in headers if k.lower() == 'content-type'), ''
        )
        if content_encoding not in {'', 'identity'} or not public_host:
            return payload, False
        proto = public_proto.split(',', 1)[0].strip().lower()
        if proto not in {'http', 'https'}:
            proto = 'http'
        public_origin = f'{proto}://{public_host}'.encode('ascii')
        rewritten = payload
        for scheme in ('http', 'https'):
            internal = f'{scheme}://{backend.netloc}'.encode('ascii')
            rewritten = rewritten.replace(internal, public_origin)
            rewritten = rewritten.replace(
                internal.replace(b'/', b'\\/'),
                public_origin.replace(b'/', b'\\/'),
            )
        rewritten = rewritten.replace(
            f'//{backend.netloc}'.encode('ascii'),
            f'//{public_host}'.encode('ascii'),
        )
        rewritten = rewritten.replace(
            backend.netloc.encode('ascii'),
            public_host.encode('ascii'),
        )
        if content_type.startswith('text/html'):
            for path in directory_links:
                encoded_path = path.encode('ascii')
                for attribute in (b'href', b'action'):
                    for quote in (bytes([34]), bytes([39])):
                        old = attribute + b'=' + quote + encoded_path + quote
                        new = (
                            attribute + b'=' + quote
                            + encoded_path + b'/' + quote
                        )
                        rewritten = rewritten.replace(old, new)
        return rewritten, rewritten != payload

    def _forward(
        self,
        method: str,
        body: bytes,
        request_id: str,
        detected_attack: bool,
    ) -> None:
        assert self.config is not None
        backend = self.config.backend_parts
        connection_cls = (
            http.client.HTTPSConnection if backend.scheme == "https"
            else http.client.HTTPConnection
        )
        port = backend.port or (443 if backend.scheme == "https" else 80)
        connection = connection_cls(backend.hostname, port, timeout=self.config.timeout)

        prefix = backend.path.rstrip("/")
        target = f"{prefix}{self.path}" if prefix else self.path
        original_host = self.headers.get("Host", "")
        public_proto = self.headers.get('X-Forwarded-Proto', 'http')
        if self.config.public_origin:
            public = urlsplit(self.config.public_origin)
            original_host = public.netloc
            public_proto = public.scheme
        request_headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
            and key.lower() not in {'host', 'content-length', 'accept-encoding'}
        }
        request_headers['Host'] = original_host or backend.netloc
        request_headers['Accept-Encoding'] = 'identity'
        request_headers["X-Forwarded-Host"] = original_host
        # TLS 通常由前置 Nginx/Apache/IIS 终止；优先保留其声明的原始客户端协议，
        # 不能用 WAD 到上游的内部协议覆盖它。
        request_headers['X-Forwarded-Proto'] = public_proto
        _, forwarded_chain = self._client_chain()
        request_headers["X-Forwarded-For"] = forwarded_chain
        request_headers["X-WAD-Request-ID"] = request_id
        if detected_attack and self.config.mode == "monitor":
            request_headers["X-WAD-Monitor-Verdict"] = "attack"

        try:
            connection.request(method, target, body=body or None, headers=request_headers)
            response = connection.getresponse()
            response_headers = response.getheaders()
            rewritten_headers = []
            redirect_rewritten = False
            for key, value in response_headers:
                if key.lower() == 'location':
                    new_value = self._rewrite_location(
                        value, backend, original_host, public_proto
                    )
                    redirect_rewritten = redirect_rewritten or new_value != value
                    value = new_value
                rewritten_headers.append((key, value))
            response_headers = rewritten_headers
            response_status = response.status
            if redirect_rewritten and response_status == 301:
                response_status = 302
            elif redirect_rewritten and response_status == 308:
                response_status = 307
            response_body = response.read()
            if method == "HEAD":
                body_rewritten = False
            else:
                response_body, body_rewritten = self._rewrite_response_body(
                    response_body, response_headers, backend, original_host,
                    public_proto, self.config.directory_links
                )
            if response_status == response.status:
                self.send_response(response_status, response.reason)
            else:
                self.send_response(response_status)
            sent_content_length = False
            for key, value in response_headers:
                lower_key = key.lower()
                if body_rewritten and lower_key in {'etag', 'content-md5'}:
                    continue
                if redirect_rewritten and lower_key in {
                    'cache-control', 'expires', 'pragma'
                }:
                    continue
                if method == "HEAD" and lower_key == "content-length":
                    self.send_header(key, value)
                    sent_content_length = True
                elif lower_key not in HOP_BY_HOP_HEADERS and lower_key != 'content-length':
                    self.send_header(key, value)
            if redirect_rewritten:
                self.send_header('Cache-Control', 'no-store, max-age=0')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
            if method != "HEAD" or not sent_content_length:
                self.send_header("Content-Length", str(len(response_body)))
            self.send_header("X-WAD-Request-ID", request_id)
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(response_body)
        finally:
            connection.close()

    def _send_json(self, status: int, value: dict, request_id: str) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-WAD-Request-ID", request_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _write_log(
        self,
        method: str,
        request_id: str,
        threats: list[dict],
        started: float,
        detection_elapsed_ms: float,
        outcome: str,
        error: str | None,
    ) -> None:
        assert self.config is not None
        if self.config.log_file is None:
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "client_ip": self._client_chain()[0],
            "method": method,
            # 不记录 query 和请求体，避免令牌/隐私数据进入访问日志。
            "path": urlsplit(self.path).path,
            "mode": self.config.mode,
            "outcome": outcome,
            "threat_count": len(threats),
            "threats": threats,
            "error": error,
            "detection_elapsed_ms": round(detection_elapsed_ms, 3),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self.log_lock:
            try:
                self.config.log_file.parent.mkdir(parents=True, exist_ok=True)
                with self.config.log_file.open('a', encoding='utf-8') as handle:
                    handle.write(line)
            except OSError as exc:
                sys.stderr.write(
                    f'[proxy] access log write failed: {type(exc).__name__}: {exc}\n'
                )
                sys.stderr.flush()

    @classmethod
    def _write_status(cls) -> None:
        """Publish a heartbeat in the shared runtime volume for the dashboard."""

        assert cls.config is not None
        if cls.config.log_file is None:
            return
        status_path = cls.config.log_file.with_name("proxy_status.json")
        temporary = status_path.with_name(f".{status_path.name}.{os.getpid()}.tmp")
        value = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": cls.config.mode,
            "fail_policy": cls.config.fail_policy,
            "backend": cls.config.backend,
            "public_origin": cls.config.public_origin,
            "models_loaded": cls.pipeline is not None,
        }
        with cls.log_lock:
            try:
                status_path.parent.mkdir(parents=True, exist_ok=True)
                temporary.write_text(
                    json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                os.replace(temporary, status_path)
            except OSError as exc:
                sys.stderr.write(
                    f"[proxy] status heartbeat write failed: {type(exc).__name__}: {exc}\n"
                )
                sys.stderr.flush()

    def _refresh_runtime_control(self) -> None:
        """Hot-load authenticated dashboard changes from the shared volume."""

        assert self.config is not None
        if self.config.log_file is None:
            return
        control_path = self.config.log_file.with_name("proxy_control.json")
        try:
            mtime_ns = control_path.stat().st_mtime_ns
        except OSError:
            return
        if mtime_ns == type(self).control_mtime_ns:
            return
        with self.control_lock:
            if mtime_ns == type(self).control_mtime_ns:
                return
            try:
                value = json.loads(control_path.read_text(encoding="utf-8"))
                mode = value.get("mode")
                fail_policy = value.get("fail_policy")
                if mode not in {"monitor", "block"}:
                    raise ValueError("mode must be monitor or block")
                if fail_policy not in {"open", "closed"}:
                    raise ValueError("fail_policy must be open or closed")
                type(self).config = replace(
                    self.config, mode=mode, fail_policy=fail_policy
                )
                type(self).control_mtime_ns = mtime_ns
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                sys.stderr.write(
                    f"[proxy] runtime control ignored: {type(exc).__name__}: {exc}\n"
                )
                sys.stderr.flush()


class WAFThreadingHTTPServer(ThreadingHTTPServer):
    """请求线程在进程退出时自动结束。"""

    daemon_threads = True
    allow_reuse_address = True


def load_final_pipeline() -> DetectionPipeline:
    """加载唯一最终模型；文件不完整时拒绝启动代理。"""

    pipeline = DetectionPipeline()
    pipeline.load_lgbm(str(MODEL_ROOT / "lgbm_v4.pkl"))
    pipeline.load_text_model(str(MODEL_ROOT / "text_lr_v4.pkl"))
    if pipeline.lgbm_model is None or pipeline.text_model is None:
        raise RuntimeError("最终模型文件未完整加载")
    # Trigger lazy native-library/thread initialization before accepting the
    # first real request. This value follows the same L2 + text path as a
    # typical browser User-Agent and is benign by regression coverage.
    pipeline.detect(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "header",
        "User-Agent",
    )
    return pipeline


def configure_handler(pipeline: DetectionPipeline, config: ProxyConfig) -> None:
    """配置处理器；单独提供函数便于端到端测试。"""

    config.backend_parts  # 启动前校验 URL。
    if config.public_origin:
        public = urlsplit(config.public_origin)
        if (
            public.scheme not in {'http', 'https'}
            or not public.netloc
            or public.path not in {'', '/'}
            or public.query
            or public.fragment
        ):
            raise ValueError('public-origin 必须只包含 http(s)://主机[:端口]')
    for path in config.directory_links:
        if (
            not path.startswith('/')
            or path == '/'
            or path.endswith('/')
            or any(mark in path for mark in ('?', '#', '\\'))
        ):
            raise ValueError('directory-links 必须是无尾斜杠的绝对路径')
    try:
        for cidr in config.trusted_proxy_cidrs:
            ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"trusted-proxies 包含无效 CIDR: {exc}") from exc
    WAFProxyHandler.pipeline = pipeline
    # A newly configured model or allowlist must never inherit decisions made
    # under the previous runtime configuration.
    WAFProxyHandler.result_cache = FeatureCache(maxsize=10000)
    WAFProxyHandler.config = config
    WAFProxyHandler.control_mtime_ns = None
    WAFProxyHandler.scanner_detector = ScannerBehaviorDetector()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WAD 通用前置反向代理")
    parser.add_argument(
        "--host", default=os.environ.get("WAD_PROXY_HOST", "0.0.0.0"),
        help="监听地址，默认 0.0.0.0",
    )
    parser.add_argument(
        "--port", "--listen", dest="port", type=int,
        default=int(os.environ.get("WAD_PROXY_PORT", "8081")),
        help="监听端口，默认 8081",
    )
    parser.add_argument(
        "--backend", default=os.environ.get("WAD_PROXY_BACKEND", "http://127.0.0.1:3000"),
        help="业务上游 URL",
    )
    parser.add_argument(
        '--public-origin',
        default=os.environ.get('WAD_PROXY_PUBLIC_ORIGIN', ''),
        help='用户实际访问的公网入口，例如 http://122.51.242.77:8081',
    )
    parser.add_argument(
        '--directory-links',
        default=os.environ.get('WAD_PROXY_DIRECTORY_LINKS', ''),
        help='逗号分隔的目录链接，例如 /pwd,/apply',
    )
    parser.add_argument(
        '--trusted-proxies',
        default=os.environ.get(
            'WAD_PROXY_TRUSTED_PROXIES', ','.join(DEFAULT_TRUSTED_PROXY_CIDRS)
        ),
        help='可信反向代理 CIDR，逗号分隔；默认仅信任本机回环地址',
    )
    parser.add_argument(
        '--field-allowlist',
        default=os.environ.get('WAD_PROXY_FIELD_ALLOWLIST', ''),
        help=(
            '逗号分隔的业务字段精确放行项，格式 '
            '/path:location:name；仅用于上游已鉴权并安全处理的字段'
        ),
    )
    parser.add_argument(
        "--mode", choices=["monitor", "block"],
        default=os.environ.get("WAD_PROXY_MODE", "monitor"),
        help="monitor 只记录；block 阻断攻击",
    )
    parser.add_argument(
        "--fail-policy", choices=["open", "closed"],
        default=os.environ.get("WAD_PROXY_FAIL_POLICY", "closed"),
        help="检测器异常时放行或返回 503，默认 closed",
    )
    parser.add_argument(
        "--timeout", type=float,
        default=float(os.environ.get("WAD_PROXY_TIMEOUT", "30")),
        help="上游超时秒数",
    )
    parser.add_argument(
        "--max-body-mb", type=float,
        default=float(os.environ.get("WAD_PROXY_MAX_BODY_MB", "1")),
        help="最大请求体 MiB，默认 1",
    )
    parser.add_argument(
        "--log-file", default=os.environ.get(
            "WAD_PROXY_LOG_FILE", str(RUNTIME_ROOT / "proxy_access.jsonl")
        ),
        help="UTF-8 JSONL 访问日志",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not (1 <= args.port <= 65535):
        raise SystemExit("port 必须在 1..65535")
    if args.max_body_mb <= 0:
        raise SystemExit("max-body-mb 必须大于 0")

    ensure_runtime_dirs()
    config = ProxyConfig(
        backend=args.backend,
        mode=args.mode,
        fail_policy=args.fail_policy,
        timeout=args.timeout,
        max_body_bytes=int(args.max_body_mb * 1024 * 1024),
        log_file=Path(args.log_file).expanduser().resolve() if args.log_file else None,
        public_origin=args.public_origin.strip() or None,
        directory_links=tuple(
            item.strip() for item in args.directory_links.split(',')
            if item.strip()
        ),
        trusted_proxy_cidrs=tuple(
            item.strip() for item in args.trusted_proxies.split(',')
            if item.strip()
        ),
        field_allowlist=parse_field_allowlist(args.field_allowlist),
    )
    try:
        pipeline = load_final_pipeline()
        configure_handler(pipeline, config)
    except Exception as exc:
        raise SystemExit(f"代理启动失败：{exc}") from exc

    server = WAFThreadingHTTPServer((args.host, args.port), WAFProxyHandler)
    heartbeat_stop = threading.Event()

    def publish_heartbeat() -> None:
        while not heartbeat_stop.wait(30):
            WAFProxyHandler._write_status()

    # The operations dashboard must not depend on a Docker-specific
    # healthcheck. Publish immediately, then refresh while the proxy lives.
    WAFProxyHandler._write_status()
    heartbeat_thread = threading.Thread(
        target=publish_heartbeat,
        name="wad-proxy-heartbeat",
        daemon=True,
    )
    heartbeat_thread.start()
    print("WAD 前置反向代理已启动")
    print(f"  入口: http://{args.host}:{args.port}")
    print(f"  上游: {args.backend}")
    print(f"  公网入口: {config.public_origin or '按请求 Host 自动识别'}")
    print(f"  模式: {args.mode} / 检测故障策略: fail-{args.fail_policy}")
    print(f"  健康: http://127.0.0.1:{args.port}/_wad/health")
    print(f"  日志: {config.log_file or 'disabled'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止代理…")
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=2)
        server.server_close()


if __name__ == "__main__":
    main()
