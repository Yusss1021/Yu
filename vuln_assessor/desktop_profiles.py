from __future__ import annotations

import shlex

from .config import parse_methods

DEFAULT_DISCOVERY_PRESET = "progressive"
DEFAULT_ANALYSIS_PRESET = "standard"

DISCOVERY_PRESET_METHODS: dict[str, list[str]] = {
    "progressive": ["icmp", "arp", "syn"],
}

ANALYSIS_PRESET_ARGUMENTS: dict[str, list[str]] = {
    "quick": ["-sV", "-Pn", "--version-light"],
    "standard": ["-sV", "-Pn", "--version-intensity", "5"],
    "deep": ["-sV", "-Pn", "--version-all"],
}


def resolve_discovery_methods(preset: str, raw_methods: str | None) -> list[str]:
    normalized = preset.strip().lower()
    if normalized in DISCOVERY_PRESET_METHODS:
        return list(DISCOVERY_PRESET_METHODS[normalized])
    return parse_methods(raw_methods)


def resolve_nmap_arguments(profile: str, extra_args: str | None = None) -> list[str]:
    normalized = profile.strip().lower()
    base_arguments = list(ANALYSIS_PRESET_ARGUMENTS.get(normalized, ANALYSIS_PRESET_ARGUMENTS[DEFAULT_ANALYSIS_PRESET]))
    if not extra_args or not extra_args.strip():
        return base_arguments
    return base_arguments + shlex.split(extra_args.strip())
