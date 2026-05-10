from __future__ import annotations

import json
from pathlib import Path


def load_asset_profile(profile_path: Path | None) -> tuple[dict[str, float], float]:
    if profile_path is None:
        return {}, 5.0
    if not profile_path.exists():
        raise FileNotFoundError(f"asset profile file not found: {profile_path}")

    with profile_path.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)
    if not isinstance(payload, dict):
        raise ValueError("asset profile must be a JSON object")

    default_value = _to_score(payload.get("default_criticality", 5.0), fallback=5.0)
    raw_assets = payload.get("assets", {})
    if raw_assets is None:
        raw_assets = {}
    if not isinstance(raw_assets, dict):
        raise ValueError("asset profile key 'assets' must be an object")

    result: dict[str, float] = {}
    for host_ip, raw_score in raw_assets.items():
        result[str(host_ip)] = _to_score(raw_score, fallback=default_value)
    return result, default_value


def _to_score(raw_value: object, fallback: float) -> float:
    try:
        score = float(raw_value)
    except (TypeError, ValueError):
        return fallback
    return max(0.0, min(score, 10.0))
