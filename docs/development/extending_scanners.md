# 如何添加新扫描器

> 扩展 VulnScanner 的主机发现和服务识别能力

---

## 概述

VulnScanner 的扫描器分为两类：

| 类型 | 基类 | 功能 | 示例 |
|------|------|------|------|
| 主机发现 | `AssetScanner` | 发现网络中存活的主机 | ICMP、ARP、SYN |
| 服务识别 | `ServiceScanner` | 识别主机上运行的服务 | Nmap |

---

## 1. 扫描器基类

所有扫描器都定义在 `src/vulnscan/core/base.py`：

```python
class Scanner(ABC):
    """扫描器抽象基类"""

    @abstractmethod
    def scan(self, context: ScanContext) -> ScanResult:
        """执行扫描"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """返回扫描器名称"""
        pass


class AssetScanner(Scanner, ABC):
    """主机发现扫描器基类"""
    pass


class ServiceScanner(Scanner, ABC):
    """服务识别扫描器基类"""
    pass
```

---

## 2. 核心数据结构

### ScanContext - 扫描上下文

```python
@dataclass
class ScanContext:
    target_range: str                      # 扫描目标（CIDR/范围/IP）
    scan_id: int                           # 扫描任务 ID
    options: Dict[str, Any]                # 扫描选项
    discovered_hosts: List[Host]           # 已发现的主机
    discovered_services: List[Service]     # 已发现的服务
```

### ScanResult - 扫描结果

```python
@dataclass
class ScanResult:
    hosts: List[Host] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
```

### Host - 主机信息

```python
@dataclass
class Host:
    ip: str                    # IP 地址
    mac: Optional[str]         # MAC 地址
    hostname: Optional[str]    # 主机名
    os_guess: Optional[str]    # 操作系统猜测
    scan_id: Optional[int]     # 扫描任务 ID
    id: Optional[int]          # 数据库主键
```

### Service - 服务信息

```python
@dataclass
class Service:
    host_id: int               # 所属主机 ID
    port: int                  # 端口号
    proto: str = "tcp"         # 协议（tcp/udp）
    service_name: str = ""     # 服务名称
    product: str = ""          # 产品名称
    version: str = ""          # 版本号
    cpe: str = ""              # CPE 标识符
    state: str = "open"        # 端口状态
    banner: str = ""           # Banner 信息
```

---

## 3. 实现新的主机发现扫描器

### 示例：UDP 扫描器

```python
# src/vulnscan/scanners/discovery/udp.py

import socket
import logging
from typing import List

from scapy.all import IP, UDP, sr1, ICMP

from vulnscan.core.base import AssetScanner, ScanContext, ScanResult
from vulnscan.core.models import Host
from vulnscan.utils.network import parse_target_range

logger = logging.getLogger(__name__)


class UDPScanner(AssetScanner):
    """基于 UDP 探测的主机发现扫描器"""

    def __init__(self, timeout: float = 2.0, ports: List[int] = None):
        """
        初始化 UDP 扫描器

        Args:
            timeout: 响应超时时间（秒）
            ports: 要探测的 UDP 端口列表
        """
        self.timeout = timeout
        self.ports = ports or [53, 123, 161, 500]  # DNS, NTP, SNMP, IKE

    @property
    def name(self) -> str:
        return "UDP Scanner"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        执行 UDP 扫描发现存活主机

        Args:
            context: 扫描上下文

        Returns:
            包含发现主机的扫描结果
        """
        hosts = []
        target_ips = parse_target_range(context.target_range)

        for ip in target_ips:
            if self._is_alive(ip):
                hosts.append(Host(ip=ip))
                logger.info(f"UDP 发现主机: {ip}")

        return ScanResult(hosts=hosts)

    def _is_alive(self, ip: str) -> bool:
        """通过 UDP 探测判断主机是否存活"""
        for port in self.ports:
            try:
                # 发送 UDP 包
                pkt = IP(dst=ip) / UDP(dport=port)
                reply = sr1(pkt, timeout=self.timeout, verbose=0)

                if reply is not None:
                    # 收到任何响应都表示主机存活
                    return True

                    # ICMP 端口不可达也表示主机存活
                    if reply.haslayer(ICMP):
                        if reply[ICMP].type == 3:  # Destination Unreachable
                            return True

            except Exception as e:
                logger.debug(f"UDP 探测 {ip}:{port} 失败: {e}")

        return False
```

### 代码解析

1. **继承 `AssetScanner`**：表明这是主机发现扫描器
2. **实现 `name` 属性**：返回扫描器名称，用于日志和 UI
3. **实现 `scan()` 方法**：
   - 从 `context.target_range` 解析目标 IP
   - 对每个 IP 执行探测
   - 返回 `ScanResult` 包含发现的 `Host` 对象

---

## 4. 实现新的服务识别扫描器

### 示例：Banner 抓取扫描器

```python
# src/vulnscan/scanners/service/banner.py

import socket
import logging
from typing import List

from vulnscan.core.base import ServiceScanner, ScanContext, ScanResult
from vulnscan.core.models import Service

logger = logging.getLogger(__name__)


class BannerScanner(ServiceScanner):
    """通过 Banner 抓取识别服务"""

    # 常见服务的默认端口和探测字符串
    PROBES = {
        21: (b"", "ftp"),           # FTP 无需发送数据
        22: (b"", "ssh"),           # SSH 无需发送数据
        25: (b"EHLO test\r\n", "smtp"),
        80: (b"HEAD / HTTP/1.0\r\n\r\n", "http"),
        110: (b"", "pop3"),
        143: (b"", "imap"),
        3306: (b"", "mysql"),
    }

    def __init__(self, timeout: float = 3.0, ports: List[int] = None):
        self.timeout = timeout
        self.ports = ports or list(self.PROBES.keys())

    @property
    def name(self) -> str:
        return "Banner Grabber"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        对已发现的主机执行 Banner 抓取

        Args:
            context: 扫描上下文（包含 discovered_hosts）

        Returns:
            包含识别服务的扫描结果
        """
        services = []

        for host in context.discovered_hosts:
            for port in self.ports:
                service = self._grab_banner(host.ip, port, host.id)
                if service:
                    services.append(service)

        return ScanResult(services=services)

    def _grab_banner(self, ip: str, port: int, host_id: int) -> Service:
        """抓取指定端口的 Banner"""
        probe, default_service = self.PROBES.get(port, (b"", "unknown"))

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # 发送探测数据（如果有）
            if probe:
                sock.send(probe)

            # 接收 Banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            # 解析 Banner 提取产品和版本
            product, version = self._parse_banner(banner, default_service)

            return Service(
                host_id=host_id,
                port=port,
                proto="tcp",
                service_name=default_service,
                product=product,
                version=version,
                banner=banner[:200],  # 截断过长的 Banner
            )

        except Exception as e:
            logger.debug(f"Banner 抓取 {ip}:{port} 失败: {e}")
            return None

    def _parse_banner(self, banner: str, service: str) -> tuple:
        """从 Banner 中提取产品和版本"""
        # SSH 示例: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        if service == "ssh" and banner.startswith("SSH"):
            parts = banner.split("-")
            if len(parts) >= 3:
                version_part = parts[2].split()[0]
                return "OpenSSH", version_part.replace("OpenSSH_", "")

        # HTTP 示例: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"
        if service == "http" and "Server:" in banner:
            for line in banner.split("\n"):
                if line.startswith("Server:"):
                    server = line.split(":", 1)[1].strip()
                    if "/" in server:
                        product, version = server.split("/", 1)
                        return product, version.split()[0]
                    return server, ""

        return "", ""
```

---

## 5. 注册到扫描流水线

修改 `src/vulnscan/core/pipeline.py`：

### 5.1 添加导入

```python
# 在文件顶部添加导入
from ..scanners.discovery.udp import UDPScanner
from ..scanners.service.banner import BannerScanner
```

### 5.2 集成到主机发现

```python
# 在 _discover_hosts() 方法中添加
def _discover_hosts(self, target_range: str, method: str, port_range: str) -> List[Host]:
    context = ScanContext(target_range=target_range, scan_id=0)
    all_hosts = {}

    # 现有扫描器...
    if method in ("icmp", "all"):
        # ...

    if method in ("arp", "all"):
        # ...

    if method in ("syn", "all"):
        # ...

    # 添加 UDP 扫描支持
    if method in ("udp", "all"):
        try:
            scanner = UDPScanner()
            result = scanner.scan(context)
            for host in result.hosts:
                if host.ip not in all_hosts:
                    all_hosts[host.ip] = host
        except Exception as e:
            logger.warning(f"UDP scan failed: {e}")

    return list(all_hosts.values())
```

### 5.3 集成服务识别（可选）

如果要替换或补充 Nmap 扫描：

```python
def _identify_services(self, hosts: List[Host], port_range: str) -> List[Service]:
    # 可以使用 Banner 扫描器作为快速备选
    if self.use_banner_scan:
        context = ScanContext(target_range="", scan_id=0)
        context.discovered_hosts = hosts
        scanner = BannerScanner()
        return scanner.scan(context).services

    # 默认使用 Nmap
    scanner = NmapScanner(port_range=port_range)
    # ...
```

---

## 6. 更新 CLI 支持

修改 `cli/main.py` 以支持新的扫描方法：

```python
@click.option(
    "--method", "-m",
    type=click.Choice(["icmp", "arp", "syn", "udp", "all"]),  # 添加 udp
    default="icmp",
    help="主机发现方式",
)
def scan(target, method, ...):
    # ...
```

---

## 7. 最佳实践

### 7.1 错误处理

```python
def scan(self, context: ScanContext) -> ScanResult:
    hosts = []
    for ip in target_ips:
        try:
            if self._is_alive(ip):
                hosts.append(Host(ip=ip))
        except Exception as e:
            # 记录错误但继续扫描其他目标
            logger.warning(f"扫描 {ip} 时出错: {e}")
    return ScanResult(hosts=hosts)
```

### 7.2 性能优化

```python
import concurrent.futures

def scan(self, context: ScanContext) -> ScanResult:
    target_ips = parse_target_range(context.target_range)

    # 并发扫描
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(self._is_alive, target_ips))

    hosts = [
        Host(ip=ip)
        for ip, alive in zip(target_ips, results)
        if alive
    ]
    return ScanResult(hosts=hosts)
```

### 7.3 配置化

```python
from vulnscan.config import get_config

class UDPScanner(AssetScanner):
    def __init__(self, timeout: float = None):
        config = get_config()
        self.timeout = timeout or config.scan.timeout
```

---

## 8. 测试

### 单元测试示例

```python
# tests/scanners/test_udp.py

import pytest
from unittest.mock import patch, MagicMock

from vulnscan.scanners.discovery.udp import UDPScanner
from vulnscan.core.base import ScanContext


class TestUDPScanner:
    def test_name(self):
        scanner = UDPScanner()
        assert scanner.name == "UDP Scanner"

    @patch("vulnscan.scanners.discovery.udp.sr1")
    def test_scan_finds_host(self, mock_sr1):
        # 模拟收到响应
        mock_sr1.return_value = MagicMock()

        scanner = UDPScanner()
        context = ScanContext(target_range="192.168.1.1", scan_id=1)
        result = scanner.scan(context)

        assert len(result.hosts) == 1
        assert result.hosts[0].ip == "192.168.1.1"

    @patch("vulnscan.scanners.discovery.udp.sr1")
    def test_scan_no_response(self, mock_sr1):
        # 模拟无响应
        mock_sr1.return_value = None

        scanner = UDPScanner()
        context = ScanContext(target_range="192.168.1.1", scan_id=1)
        result = scanner.scan(context)

        assert len(result.hosts) == 0
```

---

## 9. 文件位置速查

| 文件 | 功能 |
|------|------|
| `src/vulnscan/core/base.py` | 扫描器基类定义 |
| `src/vulnscan/core/models.py` | 数据模型定义 |
| `src/vulnscan/core/pipeline.py` | 扫描流水线（注册扫描器） |
| `src/vulnscan/scanners/discovery/` | 主机发现扫描器目录 |
| `src/vulnscan/scanners/service/` | 服务识别扫描器目录 |
| `src/vulnscan/utils/network.py` | 网络工具函数 |

---

## 下一步

- [如何添加新验证器](extending_verifiers.md)
- [扫描器模块详解](../modules/02_scanners.md)
- [核心模块详解](../modules/01_core.md)
