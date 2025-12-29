# 如何添加新验证器

> 扩展 VulnScanner 的主动安全检测能力

---

## 概述

验证器（Verifier）用于对发现的服务进行主动安全检测，与被动的 CVE 匹配不同，验证器会实际探测目标服务。

**现有验证器**：

| 验证器 | 功能 |
|--------|------|
| `NseVulnVerifier` | Nmap NSE 漏洞脚本 |
| `WeakPasswordVerifier` | 弱密码检测 |
| `TlsAuditVerifier` | SSL/TLS 配置审计 |

---

## 1. 验证器基类

所有验证器继承 `ServiceVerifier`（定义在 `src/vulnscan/verifiers/base.py`）：

```python
from abc import ABC, abstractmethod
from typing import List

from ..core.models import Service, VerificationResult


class ServiceVerifier(ABC):
    """服务验证器基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """返回验证器名称"""
        pass

    @abstractmethod
    def verify(self, services: List[Service]) -> List[VerificationResult]:
        """
        对服务列表执行验证

        Args:
            services: 待验证的服务列表

        Returns:
            验证结果列表
        """
        pass
```

---

## 2. 核心数据结构

### Service - 服务信息

```python
@dataclass
class Service:
    host_id: int               # 所属主机 ID
    port: int                  # 端口号
    proto: str = "tcp"         # 协议
    service_name: str = ""     # 服务名称（ssh, http, mysql）
    product: str = ""          # 产品名称（OpenSSH, Apache）
    version: str = ""          # 版本号
    cpe: str = ""              # CPE 标识符
    state: str = "open"        # 端口状态
    banner: str = ""           # Banner 信息

    # 辅助属性
    host_ip: str = ""          # 主机 IP（运行时填充）
```

### VerificationResult - 验证结果

```python
@dataclass
class VerificationResult:
    scan_id: int                      # 扫描任务 ID
    host_id: int                      # 主机 ID
    service_id: Optional[int] = None  # 服务 ID
    id: Optional[int] = None          # 数据库主键
    verifier: str = ""                # 验证器名称
    name: str = ""                    # 问题名称
    severity: Severity = Severity.LOW # 严重程度
    cve_id: Optional[str] = None      # 关联的 CVE
    description: Optional[str] = None # 问题描述
    evidence: Optional[str] = None    # 证据
    detected_at: Optional[datetime] = None  # 检测时间
```

### Severity - 严重程度

```python
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

---

## 3. 实现新验证器

### 示例：HTTP 安全头检测

```python
# src/vulnscan/verifiers/http_headers.py

import logging
import requests
from datetime import datetime
from typing import List

from vulnscan.core.models import Service, VerificationResult, Severity
from vulnscan.verifiers.base import ServiceVerifier
from vulnscan.config import get_config

logger = logging.getLogger(__name__)


class HttpSecurityVerifier(ServiceVerifier):
    """检测 HTTP 安全响应头"""

    # 必须存在的安全头
    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "缺少 X-Frame-Options 头，可能存在点击劫持风险",
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "缺少 X-Content-Type-Options 头，可能存在 MIME 类型混淆风险",
        },
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "description": "缺少 HSTS 头，可能存在降级攻击风险",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "缺少 CSP 头，可能存在 XSS 风险",
        },
    }

    # 不应存在的危险头
    DANGEROUS_HEADERS = {
        "Server": {
            "severity": Severity.LOW,
            "description": "Server 头泄露服务器信息",
        },
        "X-Powered-By": {
            "severity": Severity.LOW,
            "description": "X-Powered-By 头泄露技术栈信息",
        },
    }

    def __init__(self, timeout: float = None):
        config = get_config()
        self.timeout = timeout or config.scan.timeout

    @property
    def name(self) -> str:
        return "HTTP Security Headers"

    def verify(self, services: List[Service]) -> List[VerificationResult]:
        """检测所有 HTTP 服务的安全头"""
        results = []

        for svc in services:
            if not self._is_http_service(svc):
                continue

            try:
                headers = self._fetch_headers(svc)
                results.extend(self._check_headers(svc, headers))
            except Exception as e:
                logger.debug(f"检测 {svc.host_ip}:{svc.port} 失败: {e}")

        return results

    def _is_http_service(self, svc: Service) -> bool:
        """判断是否为 HTTP 服务"""
        http_ports = {80, 443, 8080, 8443, 8000, 3000}
        http_services = {"http", "https", "http-proxy", "http-alt"}
        return svc.port in http_ports or svc.service_name in http_services

    def _fetch_headers(self, svc: Service) -> dict:
        """获取 HTTP 响应头"""
        scheme = "https" if svc.port in (443, 8443) else "http"
        url = f"{scheme}://{svc.host_ip}:{svc.port}/"

        response = requests.head(
            url,
            timeout=self.timeout,
            verify=False,  # 忽略证书错误
            allow_redirects=False,
        )
        return dict(response.headers)

    def _check_headers(self, svc: Service, headers: dict) -> List[VerificationResult]:
        """检查安全头配置"""
        results = []
        header_names = {k.lower(): k for k in headers.keys()}

        # 检查缺失的必须头
        for header, info in self.REQUIRED_HEADERS.items():
            if header.lower() not in header_names:
                results.append(self._create_result(
                    svc,
                    name=f"missing-{header.lower()}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=f"响应中未包含 {header} 头",
                ))

        # 检查存在的危险头
        for header, info in self.DANGEROUS_HEADERS.items():
            if header.lower() in header_names:
                actual_header = header_names[header.lower()]
                results.append(self._create_result(
                    svc,
                    name=f"exposed-{header.lower()}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=f"{actual_header}: {headers[actual_header]}",
                ))

        return results

    def _create_result(
        self,
        svc: Service,
        name: str,
        severity: Severity,
        description: str,
        evidence: str,
    ) -> VerificationResult:
        """创建验证结果"""
        return VerificationResult(
            scan_id=0,  # 流水线会填充
            host_id=svc.host_id,
            service_id=svc.id,
            verifier="http-headers",
            name=name,
            severity=severity,
            description=description,
            evidence=evidence,
            detected_at=datetime.now(),
        )
```

---

## 4. 更复杂的示例：目录遍历检测

```python
# src/vulnscan/verifiers/path_traversal.py

import logging
import requests
from typing import List

from vulnscan.core.models import Service, VerificationResult, Severity
from vulnscan.verifiers.base import ServiceVerifier

logger = logging.getLogger(__name__)


class PathTraversalVerifier(ServiceVerifier):
    """检测目录遍历漏洞"""

    # 常见的目录遍历 Payload
    PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ]

    # 成功的标志
    SUCCESS_PATTERNS = [
        "root:x:0:0:",
        "daemon:x:1:1:",
        "nobody:x:",
    ]

    @property
    def name(self) -> str:
        return "Path Traversal Detector"

    def verify(self, services: List[Service]) -> List[VerificationResult]:
        results = []

        for svc in services:
            if not self._is_http_service(svc):
                continue

            vuln = self._test_traversal(svc)
            if vuln:
                results.append(vuln)

        return results

    def _is_http_service(self, svc: Service) -> bool:
        return svc.port in {80, 443, 8080, 8443} or "http" in svc.service_name

    def _test_traversal(self, svc: Service) -> VerificationResult:
        """测试目录遍历漏洞"""
        scheme = "https" if svc.port in (443, 8443) else "http"
        base_url = f"{scheme}://{svc.host_ip}:{svc.port}"

        for payload in self.PAYLOADS:
            try:
                # 测试常见的参数名
                for param in ["file", "path", "page", "doc", "include"]:
                    url = f"{base_url}/?{param}={payload}"
                    response = requests.get(url, timeout=5, verify=False)

                    if self._is_vulnerable(response.text):
                        return VerificationResult(
                            scan_id=0,
                            host_id=svc.host_id,
                            service_id=svc.id,
                            verifier="path-traversal",
                            name="path-traversal-vuln",
                            severity=Severity.CRITICAL,
                            cve_id=None,
                            description="检测到目录遍历漏洞，可读取任意文件",
                            evidence=f"URL: {url}\n响应包含 /etc/passwd 内容",
                        )
            except Exception as e:
                logger.debug(f"测试失败: {e}")

        return None

    def _is_vulnerable(self, response_text: str) -> bool:
        """检查响应是否包含敏感文件内容"""
        return any(pattern in response_text for pattern in self.SUCCESS_PATTERNS)
```

---

## 5. 注册到流水线

修改 `src/vulnscan/core/pipeline.py`：

```python
# 在 _verify_services() 方法中添加
def _verify_services(self, services: List[Service]) -> List[VerificationResult]:
    from ..verifiers import (
        NseVulnVerifier,
        WeakPasswordVerifier,
        TlsAuditVerifier,
    )
    from ..verifiers.http_headers import HttpSecurityVerifier
    from ..verifiers.path_traversal import PathTraversalVerifier

    verifiers = [
        NseVulnVerifier(),
        WeakPasswordVerifier(),
        TlsAuditVerifier(),
        HttpSecurityVerifier(),      # 添加 HTTP 安全头检测
        PathTraversalVerifier(),     # 添加目录遍历检测
    ]

    results: List[VerificationResult] = []
    for verifier in verifiers:
        try:
            results.extend(verifier.verify(services))
        except Exception as e:
            logger.warning(f"Verification {verifier.name} failed: {e}")

    return results
```

---

## 6. 添加可选依赖

如果验证器需要额外的库，在 `pyproject.toml` 中添加可选依赖：

```toml
[project.optional-dependencies]
verify = [
    "paramiko>=3.0.0",      # SSH 弱密码检测
    "pymysql>=1.0.0",       # MySQL 弱密码检测
    "requests>=2.28.0",     # HTTP 检测
]
```

在代码中优雅处理缺失依赖：

```python
def verify(self, services: List[Service]) -> List[VerificationResult]:
    try:
        import requests
    except ImportError:
        logger.debug("requests 未安装，跳过 HTTP 安全头检测")
        return []

    # 正常逻辑...
```

---

## 7. 最佳实践

### 7.1 服务过滤

只处理相关服务，避免无效请求：

```python
def verify(self, services: List[Service]) -> List[VerificationResult]:
    # 只处理 HTTP 服务
    http_services = [s for s in services if self._is_http_service(s)]
    # ...
```

### 7.2 超时控制

```python
def __init__(self, timeout: float = None):
    config = get_config()
    self.timeout = timeout or config.scan.timeout

def _fetch(self, url: str):
    return requests.get(url, timeout=self.timeout)
```

### 7.3 证据收集

提供足够的证据帮助确认问题：

```python
evidence = f"""
URL: {url}
Payload: {payload}
Response Status: {response.status_code}
Response Content (前 200 字符):
{response.text[:200]}
"""
```

### 7.4 错误处理

```python
def verify(self, services: List[Service]) -> List[VerificationResult]:
    results = []
    for svc in services:
        try:
            results.extend(self._check_service(svc))
        except Exception as e:
            # 记录错误但继续检查其他服务
            logger.warning(f"检测 {svc.host_ip}:{svc.port} 失败: {e}")
    return results
```

### 7.5 速率限制

避免对目标造成过大压力：

```python
import time

def verify(self, services: List[Service]) -> List[VerificationResult]:
    results = []
    for svc in services:
        results.extend(self._check_service(svc))
        time.sleep(0.1)  # 每次请求间隔 100ms
    return results
```

---

## 8. 测试

### 单元测试示例

```python
# tests/verifiers/test_http_headers.py

import pytest
from unittest.mock import patch, MagicMock

from vulnscan.verifiers.http_headers import HttpSecurityVerifier
from vulnscan.core.models import Service, Severity


class TestHttpSecurityVerifier:
    def test_name(self):
        verifier = HttpSecurityVerifier()
        assert verifier.name == "HTTP Security Headers"

    @patch("vulnscan.verifiers.http_headers.requests.head")
    def test_missing_security_headers(self, mock_head):
        # 模拟响应缺少安全头
        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html"}
        mock_head.return_value = mock_response

        verifier = HttpSecurityVerifier()
        service = Service(host_id=1, port=80, service_name="http")
        service.host_ip = "192.168.1.1"

        results = verifier.verify([service])

        # 应该检测到缺失的安全头
        assert len(results) >= 1
        assert any(r.name == "missing-x-frame-options" for r in results)

    @patch("vulnscan.verifiers.http_headers.requests.head")
    def test_server_header_exposed(self, mock_head):
        # 模拟响应包含 Server 头
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Apache/2.4.41"}
        mock_head.return_value = mock_response

        verifier = HttpSecurityVerifier()
        service = Service(host_id=1, port=80, service_name="http")
        service.host_ip = "192.168.1.1"

        results = verifier.verify([service])

        assert any(r.name == "exposed-server" for r in results)

    def test_non_http_service_skipped(self):
        verifier = HttpSecurityVerifier()
        service = Service(host_id=1, port=22, service_name="ssh")
        service.host_ip = "192.168.1.1"

        results = verifier.verify([service])

        assert len(results) == 0
```

---

## 9. 添加修复建议

在 `src/vulnscan/remediation/knowledge_base.py` 中添加对应的修复建议：

```python
HARDENING_GUIDES = {
    # ... 现有指南

    "http-headers": {
        "name": "HTTP Security Headers",
        "recommendations": [
            {
                "title": "添加 X-Frame-Options 头",
                "description": "防止点击劫持攻击",
                "action": "添加响应头: X-Frame-Options: DENY 或 SAMEORIGIN",
                "priority": "medium",
            },
            {
                "title": "启用 HSTS",
                "description": "强制使用 HTTPS 连接",
                "action": "添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "priority": "medium",
            },
            {
                "title": "隐藏 Server 头",
                "description": "减少服务器信息泄露",
                "action": "Apache: ServerTokens Prod; Nginx: server_tokens off",
                "priority": "low",
            },
        ],
    },
}
```

---

## 10. 文件位置速查

| 文件 | 功能 |
|------|------|
| `src/vulnscan/verifiers/base.py` | 验证器基类 |
| `src/vulnscan/core/models.py` | 数据模型（Service, VerificationResult） |
| `src/vulnscan/core/pipeline.py` | 流水线（`_verify_services()` 方法） |
| `src/vulnscan/verifiers/` | 验证器目录 |
| `src/vulnscan/remediation/knowledge_base.py` | 修复建议知识库 |

---

## 下一步

- [如何添加新扫描器](extending_scanners.md)
- [主动验证模块详解](../modules/05_verifiers.md)
- [修复建议模块详解](../modules/06_remediation.md)
