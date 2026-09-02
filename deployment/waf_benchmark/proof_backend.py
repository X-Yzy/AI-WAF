#!/usr/bin/env python3
"""Minimal backend used to prove that an external WAF allowed a request.

It does not execute request content.  Every valid HTTP request is consumed and
answered with a 204 plus a dedicated proof header.  The benchmark adapter sends
traffic to the WAF endpoint, never directly to this backend.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class ProofHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "WADProofBackend/1.0"

    def respond(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        self.send_response(204)
        self.send_header("X-WAD-Benchmark-Backend", "reached")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.close_connection = True

    do_GET = respond
    do_POST = respond
    do_PUT = respond
    do_DELETE = respond
    do_PATCH = respond
    do_OPTIONS = respond

    def log_message(self, _format: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), ProofHandler)
    print(
        f"WAF benchmark proof backend listening on "
        f"http://{args.host}:{args.port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
