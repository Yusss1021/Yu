"""
Base classes for active verification.
"""

from abc import ABC, abstractmethod
from typing import List

from ..core.models import Service, VerificationResult


class ServiceVerifier(ABC):
    """Base class for service verification checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the verifier name."""
        pass

    @abstractmethod
    def verify(self, services: List[Service]) -> List[VerificationResult]:
        """
        Run verification against services.

        Args:
            services: List of services to verify

        Returns:
            List of verification results
        """
        pass
