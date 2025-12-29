"""
SSL/TLS auditing (expiry, self-signed, weak protocols).
"""

import logging
import socket
import ssl
from datetime import datetime, timedelta
from typing import List, Optional

from ..config import get_config
from ..core.models import Service, VerificationResult, Severity
from .base import ServiceVerifier

logger = logging.getLogger(__name__)


class TlsAuditVerifier(ServiceVerifier):
    """Audits SSL/TLS configurations."""

    def __init__(self, timeout: float = None, expiry_days: int = 30):
        config = get_config()
        self.timeout = timeout or config.scan.timeout
        self.expiry_days = expiry_days

    @property
    def name(self) -> str:
        return "SSL/TLS Auditor"

    def verify(self, services: List[Service]) -> List[VerificationResult]:
        results: List[VerificationResult] = []
        for svc in services:
            if not svc.id or not svc.host_id:
                continue
            if not self._is_tls_service(svc):
                continue

            cert = self._fetch_cert(svc.host_ip, svc.port)
            if cert:
                now = datetime.utcnow()
                if cert["not_after"] < now:
                    results.append(self._result(svc, "cert-expired", Severity.HIGH, cert["summary"]))
                elif cert["not_after"] < now + timedelta(days=self.expiry_days):
                    results.append(self._result(svc, "cert-expiring-soon", Severity.MEDIUM, cert["summary"]))
                if cert["self_signed"]:
                    results.append(self._result(svc, "self-signed-cert", Severity.LOW, cert["summary"]))

            # Check for weak protocols
            if self._supports_tls10(svc.host_ip, svc.port):
                results.append(self._result(svc, "tls1.0-enabled", Severity.MEDIUM, "TLSv1.0 supported"))
            if self._supports_sslv3(svc.host_ip, svc.port):
                results.append(self._result(svc, "sslv3-enabled", Severity.HIGH, "SSLv3 supported"))

        return results

    def _is_tls_service(self, svc: Service) -> bool:
        tls_ports = {443, 8443, 465, 587, 993, 995, 636, 3389}
        name = (svc.service_name or "").lower()
        return svc.port in tls_ports or "https" in name or "ssl" in name or "tls" in name

    def _fetch_cert(self, host: str, port: int) -> Optional[dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            return {"not_after": datetime.utcnow() + timedelta(days=365), "self_signed": True, "summary": "Binary cert only"}
                        return None

            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            self_signed = subject.get("commonName") == issuer.get("commonName")

            return {
                "not_after": not_after,
                "self_signed": self_signed,
                "summary": f"CN={subject.get('commonName', 'N/A')} Issuer={issuer.get('commonName', 'N/A')} Expires={cert.get('notAfter')}",
            }
        except Exception as e:
            logger.debug(f"TLS audit failed for {host}:{port}: {e}")
            return None

    def _supports_tls10(self, host: str, port: int) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _supports_sslv3(self, host: str, port: int) -> bool:
        if not hasattr(ssl, "PROTOCOL_SSLv3"):
            return False
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _result(self, svc: Service, name: str, severity: Severity, evidence: str) -> VerificationResult:
        return VerificationResult(
            scan_id=0,
            host_id=svc.host_id,
            service_id=svc.id,
            verifier="tls-audit",
            name=name,
            severity=severity,
            description=f"SSL/TLS issue: {name}",
            evidence=evidence,
            detected_at=datetime.utcnow(),
        )
