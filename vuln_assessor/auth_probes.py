from __future__ import annotations

import ftplib
from dataclasses import dataclass
from typing import Callable

FTP_WEAK_CREDENTIALS = [
    ("admin", ""),
    ("admin", "admin"),
    ("root", ""),
    ("root", "root"),
    ("ftp", "ftp"),
    ("test", "test"),
]
SSH_WEAK_CREDENTIALS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "123456"),
]
MYSQL_WEAK_CREDENTIALS = [
    ("root", ""),
    ("root", "root"),
    ("root", "123456"),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "123456"),
]

CredentialProbe = Callable[[str, int, str, str, float], bool]


@dataclass(frozen=True, slots=True)
class WeakCredentialHit:
    username: str
    password: str

    @property
    def display(self) -> str:
        password = self.password if self.password else "<empty>"
        return f"{self.username}/{password}"


class WeakCredentialProbeEngine:
    def __init__(
        self,
        timeout_seconds: float = 2.0,
        ssh_probe: CredentialProbe | None = None,
        mysql_probe: CredentialProbe | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self._ssh_probe = ssh_probe
        self._mysql_probe = mysql_probe

    def probe_ftp(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        return self._probe_with_candidates(
            host_ip=host_ip,
            port=port,
            candidates=FTP_WEAK_CREDENTIALS,
            probe=self._attempt_ftp_login,
        )

    def probe_ssh(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        probe = self._ssh_probe or self._build_default_ssh_probe()
        if probe is None:
            return None
        return self._probe_with_candidates(host_ip=host_ip, port=port, candidates=SSH_WEAK_CREDENTIALS, probe=probe)

    def probe_mysql(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        probe = self._mysql_probe or self._build_default_mysql_probe()
        if probe is None:
            return None
        return self._probe_with_candidates(host_ip=host_ip, port=port, candidates=MYSQL_WEAK_CREDENTIALS, probe=probe)

    def _probe_with_candidates(
        self,
        host_ip: str,
        port: int,
        candidates: list[tuple[str, str]],
        probe: CredentialProbe,
    ) -> WeakCredentialHit | None:
        for username, password in candidates:
            if not probe(host_ip, port, username, password, self.timeout_seconds):
                continue
            return WeakCredentialHit(username=username, password=password)
        return None

    def _attempt_ftp_login(self, host_ip: str, port: int, username: str, password: str, timeout: float) -> bool:
        client = ftplib.FTP()
        try:
            client.connect(host=host_ip, port=port, timeout=timeout)
            response = client.login(user=username, passwd=password)
            return str(response).startswith("230")
        except Exception:
            return False
        finally:
            try:
                client.quit()
            except Exception:
                client.close()

    def _build_default_ssh_probe(self) -> CredentialProbe | None:
        try:
            import paramiko
        except ImportError:
            return None

        def _probe(host_ip: str, port: int, username: str, password: str, timeout: float) -> bool:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=host_ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout,
                    auth_timeout=timeout,
                    banner_timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                return True
            except Exception:
                return False
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        return _probe

    def _build_default_mysql_probe(self) -> CredentialProbe | None:
        try:
            import pymysql
        except ImportError:
            return None

        def _probe(host_ip: str, port: int, username: str, password: str, timeout: float) -> bool:
            connection = None
            try:
                connection = pymysql.connect(
                    host=host_ip,
                    port=port,
                    user=username,
                    password=password,
                    connect_timeout=int(timeout),
                    read_timeout=int(timeout),
                    write_timeout=int(timeout),
                    charset="utf8mb4",
                )
                return True
            except Exception:
                return False
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass

        return _probe
