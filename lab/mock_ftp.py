from __future__ import annotations

import argparse
import socketserver


FTP_BANNER = b"220 (vsFTPd 3.0.3)\r\n"


class MockFtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(FTP_BANNER)
        while True:
            line = self.rfile.readline(1024)
            if not line:
                break
            command = line.decode("utf-8", errors="ignore").strip().upper()
            if command.startswith("USER"):
                self.wfile.write(b"331 Please specify the password.\r\n")
                continue
            if command.startswith("PASS"):
                self.wfile.write(b"230 Login successful.\r\n")
                continue
            if command == "SYST":
                self.wfile.write(b"215 UNIX Type: L8\r\n")
                continue
            if command == "FEAT":
                self.wfile.write(b"211-Features\r\n UTF8\r\n211 End\r\n")
                continue
            if command == "QUIT":
                self.wfile.write(b"221 Goodbye.\r\n")
                break
            self.wfile.write(b"200 Command okay.\r\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mock vsftpd-like service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2121)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with ThreadedTCPServer((args.host, args.port), MockFtpHandler) as server:
        print(f"mock_ftp started at {args.host}:{args.port}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
