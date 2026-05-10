from __future__ import annotations

from .active_check_network import SNMP_STANDARD_PORT, ftp_allows_anonymous
from .active_check_network import redis_allows_unauthenticated_commands, snmp_default_community
from .auth_probes import WeakCredentialHit, WeakCredentialProbeEngine
from .models import HostAsset, ServiceFingerprint, VulnerabilityFinding

FTP_STANDARD_PORTS = {21}
SSH_STANDARD_PORTS = {22}
MYSQL_STANDARD_PORTS = {3306}
REDIS_STANDARD_PORTS = {6379}
TELNET_STANDARD_PORTS = {23}

EXPOSURE_CHECKS = {
    "telnet": {
        "service_name": "telnet",
        "cve_id": "CFG-TELNET-OPEN-0001",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "检测到 Telnet 明文远程管理服务开放，存在凭证泄露与会话被窃听风险。",
        "remediation": "关闭 Telnet，改用 SSH 等加密管理协议。",
        "match_confidence": 9.5,
        "confidence_reason": "检测到 Telnet 服务或标准端口开放。",
        "exploit_maturity": 7.0,
    },
    "ftp_anonymous": {
        "service_name": "ftp",
        "cve_id": "CFG-FTP-ANON-0001",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "description": "FTP 服务允许匿名或空口令登录，未授权用户可能直接读取或写入文件。",
        "remediation": "关闭匿名访问，启用最小权限账户并限制 FTP 暴露范围。",
        "match_confidence": 9.8,
        "confidence_reason": "FTP 登录尝试成功，确认存在匿名访问能力。",
        "exploit_maturity": 7.5,
    },
    "redis": {
        "service_name": "redis",
        "cve_id": "CFG-REDIS-UNAUTH-0001",
        "severity": "HIGH",
        "cvss": 8.6,
        "description": "Redis 服务允许未认证访问，攻击者可能直接读取数据或执行高危管理命令。",
        "remediation": "为 Redis 配置认证与访问控制，并避免暴露在不可信网段。",
        "match_confidence": 9.8,
        "confidence_reason": "未认证 PING/INFO 请求得到有效响应。",
        "exploit_maturity": 8.5,
    },
}
AUTH_CHECKS = {
    "ftp": {
        "standard_ports": FTP_STANDARD_PORTS,
        "cve_id": "CFG-FTP-WEAK-PASSWORD-0002",
        "severity": "HIGH",
        "cvss": 8.0,
        "description": "FTP 服务存在空密码或常见弱口令，攻击者可能直接获取文件访问权限。",
        "remediation": "禁用弱口令，关闭无必要 FTP 账号，并优先迁移至 SFTP/FTPS。",
        "exploit_maturity": 8.0,
    },
    "ssh": {
        "standard_ports": SSH_STANDARD_PORTS,
        "cve_id": "CFG-SSH-WEAK-PASSWORD-0001",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "SSH 服务存在空密码或常见弱口令，攻击者可直接获取远程管理权限。",
        "remediation": "强制使用高强度密码或密钥认证，并限制 SSH 来源地址。",
        "exploit_maturity": 8.5,
    },
    "mysql": {
        "standard_ports": MYSQL_STANDARD_PORTS,
        "cve_id": "CFG-MYSQL-WEAK-PASSWORD-0001",
        "severity": "HIGH",
        "cvss": 9.0,
        "description": "MySQL 服务存在空密码或常见弱口令，攻击者可直接读取或篡改数据库内容。",
        "remediation": "重置弱口令，限制远程登录，并按最小权限拆分数据库账户。",
        "exploit_maturity": 8.8,
    },
}


class ActiveCheckEngine:
    def __init__(
        self,
        timeout_seconds: float = 2.0,
        credential_probe_engine: WeakCredentialProbeEngine | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.credential_probe_engine = credential_probe_engine or WeakCredentialProbeEngine(timeout_seconds=timeout_seconds)

    def run(
        self,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        fallback_ports: list[int],
        enable_auth_checks: bool = False,
    ) -> list[VulnerabilityFinding]:
        services_by_host = self._group_services_by_host(services)
        findings: list[VulnerabilityFinding] = []
        for asset in assets:
            host_services = services_by_host.get(asset.ip, [])
            findings.extend(self._check_telnet(asset, host_services))
            findings.extend(self._check_ftp_anonymous(asset, host_services))
            findings.extend(self._check_redis(asset, host_services))
            findings.extend(self._check_snmp(asset, host_services, fallback_ports))
            if enable_auth_checks:
                findings.extend(self._check_weak_credentials(asset, host_services))
        return self._dedupe(findings)

    def _check_telnet(self, asset: HostAsset, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        ports = self._candidate_ports(asset, services, {"telnet"}, TELNET_STANDARD_PORTS)
        return [self._build_from_spec(asset, port, EXPOSURE_CHECKS["telnet"]) for port in ports]

    def _check_ftp_anonymous(self, asset: HostAsset, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        ports = self._candidate_ports(asset, services, {"ftp"}, FTP_STANDARD_PORTS)
        return [
            self._build_from_spec(asset, port, EXPOSURE_CHECKS["ftp_anonymous"])
            for port in ports
            if ftp_allows_anonymous(asset.ip, port, self.timeout_seconds)
        ]

    def _check_redis(self, asset: HostAsset, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        ports = self._candidate_ports(asset, services, {"redis"}, REDIS_STANDARD_PORTS)
        return [
            self._build_from_spec(asset, port, EXPOSURE_CHECKS["redis"])
            for port in ports
            if redis_allows_unauthenticated_commands(asset.ip, port, self.timeout_seconds)
        ]

    def _check_snmp(
        self,
        asset: HostAsset,
        services: list[ServiceFingerprint],
        fallback_ports: list[int],
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for port in self._snmp_ports(asset, services, fallback_ports):
            community = snmp_default_community(asset.ip, port, self.timeout_seconds)
            if not community:
                continue
            findings.append(
                self._build_finding(
                    host_ip=asset.ip,
                    port=port,
                    service_name="snmp",
                    cve_id="CFG-SNMP-DEFAULT-0001",
                    severity="MEDIUM",
                    cvss=6.9,
                    description=f"SNMP 服务接受默认 community '{community}'，可能泄露资产与运行状态信息。",
                    remediation="修改默认 community，限制 SNMP 来源地址，优先升级到 SNMPv3。",
                    match_confidence=9.4,
                    confidence_reason=f"向 SNMP 端口发送默认 community '{community}' 后得到有效响应。",
                    exploit_maturity=7.0,
                    asset_criticality=asset.asset_criticality,
                )
            )
        return findings

    def _check_weak_credentials(
        self,
        asset: HostAsset,
        services: list[ServiceFingerprint],
    ) -> list[VulnerabilityFinding]:
        probes = {
            "ftp": self.credential_probe_engine.probe_ftp,
            "ssh": self.credential_probe_engine.probe_ssh,
            "mysql": self.credential_probe_engine.probe_mysql,
        }
        findings: list[VulnerabilityFinding] = []
        for service_name, spec in AUTH_CHECKS.items():
            ports = self._candidate_ports(asset, services, {service_name}, spec["standard_ports"])
            for port in ports:
                hit = probes[service_name](asset.ip, port)
                if hit is None:
                    continue
                findings.append(self._build_auth_finding(asset, port, service_name, hit, spec))
        return findings

    def _candidate_ports(
        self,
        asset: HostAsset,
        services: list[ServiceFingerprint],
        service_names: set[str],
        standard_ports: set[int],
    ) -> list[int]:
        ports = {int(item.port) for item in services if item.service_name.lower() in service_names and int(item.port) > 0}
        if not ports:
            ports = {int(port) for port in asset.open_ports if int(port) in standard_ports}
        return sorted(ports)

    def _snmp_ports(
        self,
        asset: HostAsset,
        services: list[ServiceFingerprint],
        fallback_ports: list[int],
    ) -> list[int]:
        ports = {int(item.port) for item in services if item.service_name.lower() == "snmp" and int(item.port) > 0}
        if ports:
            return sorted(ports)
        if SNMP_STANDARD_PORT in {int(port) for port in asset.open_ports if int(port) > 0}:
            return [SNMP_STANDARD_PORT]
        if SNMP_STANDARD_PORT in {int(port) for port in fallback_ports if int(port) > 0}:
            return [SNMP_STANDARD_PORT]
        return []

    def _group_services_by_host(self, services: list[ServiceFingerprint]) -> dict[str, list[ServiceFingerprint]]:
        grouped: dict[str, list[ServiceFingerprint]] = {}
        for item in services:
            grouped.setdefault(item.host_ip, []).append(item)
        return grouped

    def _dedupe(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        unique: dict[tuple[str, int, str], VulnerabilityFinding] = {}
        for item in findings:
            unique[(item.host_ip, int(item.port), item.cve_id)] = item
        return sorted(unique.values(), key=lambda item: (item.host_ip, item.port, item.cve_id))

    def _build_from_spec(self, asset: HostAsset, port: int, spec: dict[str, object]) -> VulnerabilityFinding:
        return self._build_finding(
            host_ip=asset.ip,
            port=port,
            service_name=str(spec["service_name"]),
            cve_id=str(spec["cve_id"]),
            severity=str(spec["severity"]),
            cvss=float(spec["cvss"]),
            description=str(spec["description"]),
            remediation=str(spec["remediation"]),
            match_confidence=float(spec["match_confidence"]),
            confidence_reason=str(spec["confidence_reason"]),
            exploit_maturity=float(spec["exploit_maturity"]),
            asset_criticality=asset.asset_criticality,
        )

    def _build_auth_finding(
        self,
        asset: HostAsset,
        port: int,
        service_name: str,
        hit: WeakCredentialHit,
        spec: dict[str, object],
    ) -> VulnerabilityFinding:
        return self._build_finding(
            host_ip=asset.ip,
            port=port,
            service_name=service_name,
            cve_id=str(spec["cve_id"]),
            severity=str(spec["severity"]),
            cvss=float(spec["cvss"]),
            description=str(spec["description"]),
            remediation=str(spec["remediation"]),
            match_confidence=9.9,
            confidence_reason=f"使用凭据 {hit.display} 登录成功。",
            exploit_maturity=float(spec["exploit_maturity"]),
            asset_criticality=asset.asset_criticality,
        )

    def _build_finding(
        self,
        host_ip: str,
        port: int,
        service_name: str,
        cve_id: str,
        severity: str,
        cvss: float,
        description: str,
        remediation: str,
        match_confidence: float,
        confidence_reason: str,
        exploit_maturity: float,
        asset_criticality: float,
    ) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            host_ip=host_ip,
            port=port,
            service_name=service_name,
            product="",
            version="",
            cve_id=cve_id,
            severity=severity,
            cvss=cvss,
            description=description,
            remediation=remediation,
            exploit_maturity=exploit_maturity,
            match_confidence=match_confidence,
            confidence_tier="HIGH",
            manual_confirmation_needed=False,
            confidence_reason=confidence_reason,
            asset_criticality=asset_criticality,
        )
