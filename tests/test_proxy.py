"""前置反向代理的本地端到端测试。"""

from __future__ import annotations

import json
import threading
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from src.proxy import (
    ProxyConfig,
    WAFProxyHandler,
    WAFThreadingHTTPServer,
    configure_handler,
    load_final_pipeline,
    parse_field_allowlist,
    resolve_client_chain,
)


class EchoBackend(BaseHTTPRequestHandler):
    """记录收到的方法、路径和请求体，模拟任意正常业务服务器。"""

    def do_GET(self):
        if self.path == '/links':
            internal = f'http://127.0.0.1:{self.server.server_port}/pwd/'
            payload = (
                f'<html><a href="{internal}">password</a>'
                '<a href="/pwd">pwd</a><a href="/apply">apply</a></html>'
            ).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('ETag', 'internal-body')
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == '/redirect':
            location = f'http://127.0.0.1:{self.server.server_port}/pwd/'
            self.send_response(301)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._echo("GET")

    def do_POST(self):
        self._echo("POST")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "123")
        self.end_headers()

    def do_PUT(self):
        self._echo("PUT")

    def do_PATCH(self):
        self._echo("PATCH")

    def do_DELETE(self):
        self._echo("DELETE")

    def _echo(self, method: str):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        payload = json.dumps({
            "method": method,
            "path": self.path,
            "body": body,
            "request_id": self.headers.get("X-WAD-Request-ID"),
            "forwarded_for": self.headers.get("X-Forwarded-For"),
            "monitor_verdict": self.headers.get("X-WAD-Monitor-Verdict"),
            "host": self.headers.get("Host"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        return


def _start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_proxy_forwards_normal_methods_and_blocks_attack(tmp_path):
    backend = ThreadingHTTPServer(("127.0.0.1", 0), EchoBackend)
    backend_thread = _start(backend)
    config = ProxyConfig(
        backend=f"http://127.0.0.1:{backend.server_port}",
        mode="block",
        fail_policy="closed",
        timeout=5,
        log_file=tmp_path / "proxy.jsonl",
        directory_links=('/pwd', '/apply'),
    )
    pipeline = load_final_pipeline()
    configure_handler(pipeline, config)
    proxy = WAFThreadingHTTPServer(("127.0.0.1", 0), WAFProxyHandler)
    proxy_thread = _start(proxy)
    base = f"http://127.0.0.1:{proxy.server_port}"

    try:
        normal_request = Request(
            f"{base}/hello?name=alice",
            headers={
                "Origin": base,
                "Referer": f"{base}/admin/set.php",
            },
        )
        with urlopen(normal_request, timeout=10) as response:
            forwarded = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert response.headers["X-WAD-Request-ID"]
            assert forwarded["method"] == "GET"
            assert forwarded["path"] == "/hello?name=alice"
            assert forwarded["request_id"]
            assert forwarded['host'] == f'127.0.0.1:{proxy.server_port}'

        connection = HTTPConnection('127.0.0.1', proxy.server_port, timeout=10)
        try:
            connection.request('GET', '/redirect')
            redirect = connection.getresponse()
            redirect.read()
            assert redirect.status == 302
            assert redirect.getheader('Location') == f'{base}/pwd/'
            assert redirect.getheader('Cache-Control') == 'no-store, max-age=0'
        finally:
            connection.close()

        with urlopen(f'{base}/links', timeout=10) as response:
            html = response.read().decode('utf-8')
            assert f'{base}/pwd/' in html
            assert config.backend not in html
            assert html.count('/pwd/') == 2
            assert '/apply/' in html
            assert response.headers.get('ETag') is None

        with urlopen(f'{base}/admin/theme.php', timeout=10) as response:
            assert response.status == 200

        request = Request(
            f"{base}/api/profile",
            data=b"display_name=alice",
            method="PUT",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=10) as response:
            forwarded = json.loads(response.read().decode("utf-8"))
            assert forwarded["method"] == "PUT"
            assert forwarded["body"] == "display_name=alice"

        # A narrowly configured, authenticated rich-text field may bypass
        # payload inspection without exempting its route or other fields.
        trusted_field_config = ProxyConfig(
            backend=config.backend,
            mode="block",
            fail_policy="closed",
            timeout=5,
            log_file=config.log_file,
            directory_links=config.directory_links,
            field_allowlist=parse_field_allowlist(
                "/admin/about.php:body:about"
            ),
        )
        configure_handler(pipeline, trusted_field_config)
        rich_text_request = Request(
            f"{base}/admin/about.php",
            data=b"about=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(rich_text_request, timeout=10) as response:
            assert response.status == 200
        configure_handler(pipeline, config)

        connection = HTTPConnection('127.0.0.1', proxy.server_port, timeout=10)
        try:
            connection.putrequest('POST', '/chunked')
            connection.putheader('Transfer-Encoding', 'chunked')
            connection.putheader('Content-Type', 'text/plain')
            connection.endheaders()
            connection.send(b'5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n')
            chunked = connection.getresponse()
            forwarded = json.loads(chunked.read().decode('utf-8'))
            assert chunked.status == 200
            assert forwarded['body'] == 'hello world'
        finally:
            connection.close()

        connection = HTTPConnection('127.0.0.1', proxy.server_port, timeout=10)
        try:
            connection.request('HEAD', '/download')
            head = connection.getresponse()
            assert head.status == 200
            assert head.getheader('Content-Length') == '123'
            assert head.read() == b''
        finally:
            connection.close()

        try:
            urlopen(f"{base}/search?id=-1%20union%20select%201,2,user()", timeout=10)
        except HTTPError as exc:
            assert exc.code == 403
            assert exc.headers["X-WAD-Verdict"] == "attack"
        else:
            raise AssertionError("攻击请求未被 block 模式阻断")

        monitor_config = ProxyConfig(
            backend=config.backend,
            mode="monitor",
            fail_policy="closed",
            timeout=5,
            log_file=config.log_file,
            directory_links=config.directory_links,
        )
        configure_handler(pipeline, monitor_config)
        with urlopen(f"{base}/search?id=-1%20union%20select%201,2,user()", timeout=10) as response:
            forwarded = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert forwarded["monitor_verdict"] == "attack"

        with urlopen(f"{base}/_wad/health", timeout=10) as response:
            health = json.loads(response.read().decode("utf-8"))
            assert health == {
                "status": "ok",
                "mode": "monitor",
                "backend": config.backend,
                    "public_origin": None,
                    "directory_links": ["/pwd", "/apply"],
                    "field_allowlist": [],
                    "models_loaded": True,
                "log_file": str(config.log_file),
                "log_writable": True,
            }
        status = json.loads(
            config.log_file.with_name("proxy_status.json").read_text(encoding="utf-8")
        )
        assert status["mode"] == "monitor"
        assert status["backend"] == config.backend

        config.log_file.with_name("proxy_control.json").write_text(
            json.dumps({"mode": "block", "fail_policy": "closed"}),
            encoding="utf-8",
        )
        try:
            urlopen(
                f"{base}/search?id=-1%20union%20select%201,2,user()",
                timeout=10,
            )
        except HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("运行时切换 block 后攻击请求未被阻断")

        log_lines = (tmp_path / "proxy.jsonl").read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in log_lines]
        assert {entry["outcome"] for entry in entries} >= {
            "forwarded", "blocked", "monitored_attack"
        }
        assert all("?" not in entry["path"] for entry in entries)
        assert all("detection_elapsed_ms" in entry for entry in entries)
        assert all(
            entry["elapsed_ms"] >= entry["detection_elapsed_ms"]
            for entry in entries
        )
    finally:
        proxy.shutdown()
        backend.shutdown()
        proxy.server_close()
        backend.server_close()
        proxy_thread.join(timeout=5)
        backend_thread.join(timeout=5)


def test_proxy_reuses_complete_detection_results(tmp_path):
    backend = ThreadingHTTPServer(("127.0.0.1", 0), EchoBackend)
    backend_thread = _start(backend)
    config = ProxyConfig(
        backend=f"http://127.0.0.1:{backend.server_port}",
        mode="monitor",
        fail_policy="closed",
        timeout=5,
        log_file=tmp_path / "proxy-cache.jsonl",
    )
    pipeline = load_final_pipeline()
    original_detect = pipeline.detect
    detect_calls = 0

    def counting_detect(payload, param_location="query", param_name="value"):
        nonlocal detect_calls
        detect_calls += 1
        return original_detect(payload, param_location, param_name)

    pipeline.detect = counting_detect
    configure_handler(pipeline, config)
    proxy = WAFThreadingHTTPServer(("127.0.0.1", 0), WAFProxyHandler)
    proxy_thread = _start(proxy)
    request = Request(
        f"http://127.0.0.1:{proxy.server_port}/same",
        headers={"X-WAD-Cache-Probe": "stable-normal-value"},
    )

    try:
        with urlopen(request, timeout=10) as response:
            assert response.status == 200
        first_request_calls = detect_calls
        assert first_request_calls > 0

        with urlopen(request, timeout=10) as response:
            assert response.status == 200
        assert detect_calls == first_request_calls
        assert WAFProxyHandler.result_cache.hit_rate > 0
    finally:
        proxy.shutdown()
        backend.shutdown()
        proxy.server_close()
        backend.server_close()
        proxy_thread.join(timeout=5)
        backend_thread.join(timeout=5)


def test_public_origin_rewrites_internal_address_in_any_identity_body():
    config = ProxyConfig(
        backend='http://host.docker.internal:8080',
        public_origin='http://122.51.242.77:8081',
    )
    payload = (
        b'<a href="http://host.docker.internal:8080/pwd/">pwd</a>'
    )
    body, changed = WAFProxyHandler._rewrite_response_body(
        payload,
        [('Content-Type', 'application/octet-stream')],
        config.backend_parts,
        '122.51.242.77:8081',
        'http',
    )
    assert changed
    assert b'host.docker.internal' not in body
    assert b'http://122.51.242.77:8081/pwd/' in body
    location = WAFProxyHandler._rewrite_location(
        'http://host.docker.internal:8080/pwd/',
        config.backend_parts,
        '122.51.242.77:8081',
        'http',
    )
    assert location == 'http://122.51.242.77:8081/pwd/'


def test_resolve_client_chain_enforces_the_trusted_proxy_boundary():
    trusted = ('127.0.0.0/8', '10.0.0.0/8')
    client, chain = resolve_client_chain(
        '127.0.0.1',
        '198.51.100.99, 203.0.113.8, 10.0.0.4',
        trusted,
    )
    assert client == '203.0.113.8'
    assert chain == '203.0.113.8, 10.0.0.4, 127.0.0.1'

    client, chain = resolve_client_chain(
        '192.0.2.10', '198.51.100.99', trusted
    )
    assert client == '192.0.2.10'
    assert chain == '192.0.2.10'


def test_field_allowlist_is_exact_and_validated():
    assert parse_field_allowlist(
        "/admin/about.php:body:about,/profile:header:X-Profile"
    ) == (
        ("/admin/about.php", "body", "about"),
        ("/profile", "header", "x-profile"),
    )

    for invalid in ("about", "admin:body:about", "/admin:path:value"):
        try:
            parse_field_allowlist(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"未拒绝无效放行项: {invalid}")
