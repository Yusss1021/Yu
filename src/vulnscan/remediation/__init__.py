"""
Remediation suggestions module.
"""

from .engine import RemediationEngine, get_recommendations
from .knowledge_base import HARDENING_GUIDES

__all__ = ["RemediationEngine", "get_recommendations", "HARDENING_GUIDES"]
