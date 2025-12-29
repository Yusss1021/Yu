"""
Abstract base classes for scanners.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Host, Service, ScanResult


@dataclass
class ScanContext:
    """Context object passed through the scanning pipeline."""
    target_range: str
    scan_id: int
    options: Dict[str, Any] = field(default_factory=dict)
    discovered_hosts: List[Host] = field(default_factory=list)
    discovered_services: List[Service] = field(default_factory=list)

    def with_hosts(self, hosts: List[Host]) -> "ScanContext":
        """Return a new context with updated hosts."""
        return ScanContext(
            target_range=self.target_range,
            scan_id=self.scan_id,
            options=self.options,
            discovered_hosts=hosts,
            discovered_services=self.discovered_services,
        )

    def with_services(self, services: List[Service]) -> "ScanContext":
        """Return a new context with updated services."""
        return ScanContext(
            target_range=self.target_range,
            scan_id=self.scan_id,
            options=self.options,
            discovered_hosts=self.discovered_hosts,
            discovered_services=services,
        )


class Scanner(ABC):
    """Abstract base class for all scanners."""

    @abstractmethod
    def scan(self, context: ScanContext) -> ScanResult:
        """
        Execute the scan and return results.

        Args:
            context: Scan context with target and options

        Returns:
            ScanResult containing discovered hosts/services
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass


class AssetScanner(Scanner, ABC):
    """
    Base class for asset discovery scanners.
    These scanners discover live hosts on the network.
    """
    pass


class ServiceScanner(Scanner, ABC):
    """
    Base class for service identification scanners.
    These scanners identify services running on discovered hosts.
    """
    pass


class VulnerabilityMatcher(ABC):
    """
    Abstract base class for vulnerability matchers.
    These components match services to known vulnerabilities.
    """

    @abstractmethod
    def match(self, service: Service) -> List["Vulnerability"]:
        """
        Find vulnerabilities matching the given service.

        Args:
            service: Service to match

        Returns:
            List of matching vulnerabilities
        """
        pass


class ScanPipeline:
    """
    Orchestrates the scanning workflow by running multiple scanners in sequence.
    """

    def __init__(self, stages: List[Scanner]):
        """
        Initialize the pipeline with scanner stages.

        Args:
            stages: List of scanners to run in order
        """
        self.stages = stages

    def run(self, context: ScanContext) -> ScanResult:
        """
        Execute all scanner stages and aggregate results.

        Args:
            context: Initial scan context

        Returns:
            Aggregated scan results
        """
        result = ScanResult()

        for stage in self.stages:
            stage_result = stage.scan(context)
            result.merge(stage_result)

            # Update context with discovered data for next stage
            context = context.with_hosts(
                context.discovered_hosts + stage_result.hosts
            ).with_services(
                context.discovered_services + stage_result.services
            )

        return result
