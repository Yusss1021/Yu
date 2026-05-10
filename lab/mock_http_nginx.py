from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockNginxHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.20.0"
    sys_version = ""

    def do_HEAD(self) -> None:
        self._send_headers()

    def do_GET(self) -> None:
        body = (
            "<html><head><title>Demo Nginx</title></head>"
            "<body><h1>Demo Service</h1><p>Mock nginx/1.20.0 for graduation project lab.</p></body></html>"
        ).encode("utf-8")
        self._send_headers(content_length=len(body))
        self.wfile.write(body)

    def _send_headers(self, content_length: int = 0) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(content_length))
        self.end_headers()

    def log_message(self, format_text: str, *args: object) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mock nginx-like HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), MockNginxHandler)
    print(f"mock_http_nginx started at http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
