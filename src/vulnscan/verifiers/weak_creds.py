"""
Weak password verification for SSH/MySQL/Redis/FTP.
"""

import ftplib
import logging
import socket
from datetime import datetime
from typing import List

from ..config import get_config
from ..core.models import Service, VerificationResult, Severity
from .base import ServiceVerifier

logger = logging.getLogger(__name__)

DEFAULT_PASSWORDS = [
    "", "123456", "password", "admin", "12345678", "qwerty",
    "12345", "1234", "123456789", "root",
]


class WeakPasswordVerifier(ServiceVerifier):
    """Tests common weak passwords on services."""

    def __init__(self, passwords: List[str] = None, timeout: float = None):
        config = get_config()
        self.passwords = passwords or DEFAULT_PASSWORDS
        self.timeout = timeout or config.scan.timeout

    @property
    def name(self) -> str:
        return "Weak Password Detector"

    def verify(self, services: List[Service]) -> List[VerificationResult]:
        results: List[VerificationResult] = []
        for svc in services:
            if not svc.id or not svc.host_id:
                continue
            if self._is_ssh(svc):
                results.extend(self._check_ssh(svc))
            elif self._is_mysql(svc):
                results.extend(self._check_mysql(svc))
            elif self._is_redis(svc):
                results.extend(self._check_redis(svc))
            elif self._is_ftp(svc):
                results.extend(self._check_ftp(svc))
        return results

    def _is_ssh(self, svc: Service) -> bool:
        return svc.port == 22 or (svc.service_name or "").lower() == "ssh"

    def _is_mysql(self, svc: Service) -> bool:
        return svc.port == 3306 or (svc.service_name or "").lower() in ("mysql", "mariadb")

    def _is_redis(self, svc: Service) -> bool:
        return svc.port == 6379 or (svc.service_name or "").lower() == "redis"

    def _is_ftp(self, svc: Service) -> bool:
        return svc.port == 21 or (svc.service_name or "").lower() == "ftp"

    def _result(self, svc: Service, name: str, evidence: str) -> VerificationResult:
        return VerificationResult(
            scan_id=0,
            host_id=svc.host_id,
            service_id=svc.id,
            verifier="weak-password",
            name=name,
            severity=Severity.CRITICAL,
            description="Weak or default password detected",
            evidence=evidence,
            detected_at=datetime.now(),
        )

    def _check_ssh(self, svc: Service) -> List[VerificationResult]:
        try:
            import paramiko
        except ImportError:
            logger.debug("paramiko not installed; skipping SSH checks")
            return []

        users = ["root", "admin", "user"]
        for user in users:
            for pwd in self.passwords:
                client = paramiko.SSHClient()
                try:
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        svc.host_ip, port=svc.port, username=user, password=pwd,
                        timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                        allow_agent=False, look_for_keys=False
                    )
                    return [self._result(svc, "ssh-weak-password", f"user={user} password={'<empty>' if not pwd else '******'}")]
                except Exception:
                    continue
                finally:
                    client.close()
        return []

    def _check_mysql(self, svc: Service) -> List[VerificationResult]:
        try:
            import pymysql
        except ImportError:
            logger.debug("pymysql not installed; skipping MySQL checks")
            return []

        users = ["root", "admin"]
        for user in users:
            for pwd in self.passwords:
                conn = None
                try:
                    conn = pymysql.connect(
                        host=svc.host_ip, port=svc.port, user=user, password=pwd,
                        connect_timeout=int(self.timeout)
                    )
                    return [self._result(svc, "mysql-weak-password", f"user={user} password={'<empty>' if not pwd else '******'}")]
                except Exception:
                    continue
                finally:
                    if conn:
                        conn.close()
        return []

    def _check_redis(self, svc: Service) -> List[VerificationResult]:
        # No-auth check using raw socket
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((svc.host_ip, svc.port))
            sock.send(b"PING\r\n")
            response = sock.recv(1024)
            if b"+PONG" in response:
                return [self._result(svc, "redis-no-auth", "PING succeeded without AUTH")]
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        # Check common passwords
        for pwd in self.passwords:
            if not pwd:
                continue
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((svc.host_ip, svc.port))
                sock.send(f"AUTH {pwd}\r\n".encode())
                response = sock.recv(1024)
                if b"+OK" in response:
                    return [self._result(svc, "redis-weak-password", "password=******")]
            except Exception:
                continue
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
        return []

    def _check_ftp(self, svc: Service) -> List[VerificationResult]:
        users = ["anonymous", "ftp", "admin"]
        for user in users:
            for pwd in self.passwords:
                ftp = ftplib.FTP()
                try:
                    ftp.connect(host=svc.host_ip, port=svc.port, timeout=self.timeout)
                    ftp.login(user=user, passwd=pwd if pwd else "anonymous@")
                    return [self._result(svc, "ftp-weak-password", f"user={user} password={'<empty>' if not pwd else '******'}")]
                except Exception:
                    continue
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        try:
                            ftp.close()
                        except Exception:
                            pass
        return []
