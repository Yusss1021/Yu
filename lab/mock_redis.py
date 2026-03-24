from __future__ import annotations

import argparse
import socketserver


REDIS_INFO_PAYLOAD = (
    "# Server\r\n"
    "redis_version:6.2.5\r\n"
    "redis_mode:standalone\r\n"
    "tcp_port:6379\r\n"
).encode("utf-8")


class MockRedisHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            command = self._read_command()
            if not command:
                break

            action = command[0].upper()
            if action == "PING":
                self.wfile.write(b"+PONG\r\n")
            elif action == "INFO":
                self._write_bulk(REDIS_INFO_PAYLOAD)
            elif action == "AUTH":
                self.wfile.write(b"+OK\r\n")
            elif action == "QUIT":
                self.wfile.write(b"+OK\r\n")
                break
            else:
                self.wfile.write(b"-ERR unknown command\r\n")

    def _read_command(self) -> list[str] | None:
        first_line = self.rfile.readline(4096)
        if not first_line:
            return None
        first_line = first_line.strip()
        if not first_line:
            return None

        if first_line.startswith(b"*"):
            try:
                count = int(first_line[1:])
            except ValueError:
                return None
            parts: list[str] = []
            for _ in range(count):
                length_line = self.rfile.readline(4096).strip()
                if not length_line.startswith(b"$"):
                    return None
                try:
                    part_length = int(length_line[1:])
                except ValueError:
                    return None
                content = self.rfile.read(part_length)
                self.rfile.read(2)
                parts.append(content.decode("utf-8", errors="ignore"))
            return parts

        return first_line.decode("utf-8", errors="ignore").split()

    def _write_bulk(self, payload: bytes) -> None:
        self.wfile.write(f"${len(payload)}\r\n".encode("utf-8"))
        self.wfile.write(payload)
        self.wfile.write(b"\r\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mock redis-like service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with ThreadedTCPServer((args.host, args.port), MockRedisHandler) as server:
        print(f"mock_redis started at {args.host}:{args.port}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
