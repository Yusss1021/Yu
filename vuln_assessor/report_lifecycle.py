from __future__ import annotations

import json
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def resolve_report_path(raw_path: str, report_root: Path) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate.resolve()

    root = _resolve_root(report_root)
    root_parent = root.parent
    for base in (root_parent, root, PROJECT_ROOT):
        resolved = (base / candidate).resolve()
        if resolved.exists():
            return resolved
    return (root_parent / candidate).resolve()


def delete_report_artifacts(raw_path: str, report_root: Path) -> list[str]:
    report_path = resolve_report_path(raw_path, report_root)
    if not report_path.exists():
        return []

    target = report_path.parent if report_path.is_file() and report_path.name.lower() == "report.html" else report_path
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink(missing_ok=True)
    return [str(target)]


def delete_discovery_snapshots(scan_id: int, discovery_root: Path) -> list[str]:
    root = _resolve_root(discovery_root)
    if not root.exists():
        return []

    deleted: list[str] = []
    for path in root.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        try:
            stored_scan_id = int(payload.get("scan_id"))
        except (TypeError, ValueError):
            continue
        if stored_scan_id != scan_id:
            continue
        path.unlink(missing_ok=True)
        deleted.append(str(path))
    return deleted


def _resolve_root(root: Path) -> Path:
    if root.is_absolute():
        return root.resolve()
    return (PROJECT_ROOT / root).resolve()
