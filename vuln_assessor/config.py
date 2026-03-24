from __future__ import annotations

from pathlib import Path

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
]
DEFAULT_METHODS = ["icmp", "arp"]
DEFAULT_REPORT_DIR = Path("reports")
DEFAULT_DB_PATH = Path("data/scans.db")
RULE_FILE_PATH = Path(__file__).resolve().parent / "vuln" / "rules.json"
MAX_HOSTS_PER_SCAN = 4096


def parse_ports(raw_ports: str | None) -> list[int]:
    if raw_ports is None or not raw_ports.strip():
        return DEFAULT_PORTS.copy()

    parsed_ports: list[int] = []
    invalid_tokens: list[str] = []
    for token in raw_ports.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            try:
                start = int(start_raw)
                end = int(end_raw)
            except ValueError:
                invalid_tokens.append(token)
                continue
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                invalid_tokens.append(token)
                continue
            for port in range(start, end + 1):
                parsed_ports.append(port)
            continue
        try:
            port = int(token)
        except ValueError:
            invalid_tokens.append(token)
            continue
        if 1 <= port <= 65535:
            parsed_ports.append(port)
        else:
            invalid_tokens.append(token)

    if invalid_tokens:
        joined = ", ".join(invalid_tokens)
        raise ValueError(f"无效端口参数: {joined}，端口范围应为 1-65535")

    unique_ports = sorted(set(parsed_ports))
    if not unique_ports:
        raise ValueError("端口列表不能为空")
    return unique_ports


def parse_methods(raw_methods: str | None) -> list[str]:
    if raw_methods is None or not raw_methods.strip():
        return DEFAULT_METHODS.copy()

    normalized = [item.strip().lower() for item in raw_methods.split(",") if item.strip()]
    allowed = {"icmp", "arp", "syn"}
    invalid_methods = [item for item in normalized if item not in allowed]
    if invalid_methods:
        joined = ", ".join(sorted(set(invalid_methods)))
        raise ValueError(f"无效扫描方法: {joined}，仅支持 icmp, arp, syn")

    methods = [item for item in normalized if item in allowed]
    if not methods:
        raise ValueError("扫描方法不能为空")
    return list(dict.fromkeys(methods))
