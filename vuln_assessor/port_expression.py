from __future__ import annotations

COMMON_PORT_RANGE_EXPRESSION = "1-1024"
FULL_PORT_RANGE_EXPRESSION = "1-65535"
PORT_INPUT_FORMAT_HINT = "支持 22,80,443 或 1-1024 或 1-1024,3306,6379"


def build_port_range_expression(start_raw: str, end_raw: str) -> str:
    try:
        start = int(start_raw.strip())
        end = int(end_raw.strip())
    except (TypeError, ValueError):
        raise ValueError("端口范围必须填写整数起止值。") from None
    if start < 1 or end < 1 or start > 65535 or end > 65535:
        raise ValueError("端口范围必须在 1-65535 之间。")
    if start > end:
        start, end = end, start
    return f"{start}-{end}"


def append_port_expression(existing: str, token: str) -> str:
    values = [item.strip() for item in existing.split(",") if item.strip()]
    if token not in values:
        values.append(token)
    return ",".join(values)
