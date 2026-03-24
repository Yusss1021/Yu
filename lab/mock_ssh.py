from __future__ import annotations

import argparse
import socket
import socketserver


SSH_BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"


class MockSshHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(SSH_BANNER)
        self.request.settimeout(1.0)
        try:
            self.request.recv(1024)
        except (socket.timeout, OSError):
            pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mock OpenSSH-like service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with ThreadedTCPServer((args.host, args.port), MockSshHandler) as server:
        print(f"mock_ssh started at {args.host}:{args.port}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
