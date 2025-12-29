# 面向企业内部网络的脆弱性扫描与风险评估系统

## 项目概述

本系统是一个面向企业内部网络的自动化安全评估工具，能够自动发现网络资产、识别运行服务、匹配已知漏洞并进行风险评估，最终生成专业的安全报告。

### 主要功能

- **资产发现**：支持 ICMP Ping、ARP、TCP SYN 三种扫描方式
- **服务识别**：集成 Nmap 进行服务指纹识别
- **漏洞匹配**：对接 NVD API 2.0，支持离线数据源同步
- **风险评估**：基于 CVSS 的简化风险评分模型
- **报告生成**：生成 HTML/PDF/JSON 格式的专业报告
- **扫描对比**：对比两次扫描结果，追踪安全态势变化
- **定时扫描**：支持 Cron 表达式定义周期性扫描任务
- **双界面支持**：命令行界面（CLI）和 Web 图形界面
- **双语支持**：中文/英文界面切换

---

## 目录

1. [环境要求](#环境要求)
2. [安装教程](#安装教程)
3. [快速开始](#快速开始)
4. [使用指南](#使用指南)
5. [项目结构](#项目结构)
6. [代码说明](#代码说明)
7. [API 文档](#api-文档)
8. [常见问题](#常见问题)

---

## 环境要求

### 操作系统
- Linux（推荐 Ubuntu 20.04/22.04/24.04）
- 需要 root 权限执行网络扫描

### 软件依赖
- Python 3.10 或更高版本
- Nmap 7.80 或更高版本
- SQLite3（Python 内置）

### 硬件要求
- CPU：双核及以上
- 内存：2GB 及以上
- 磁盘：500MB 可用空间

---

## 安装教程

### 第一步：安装系统依赖

```bash
# 更新软件包列表
sudo apt update

# 安装 Python 和 pip
sudo apt install -y python3 python3-pip python3-venv

# 安装 Nmap（服务识别必需）
sudo apt install -y nmap

# 安装网络工具（可选，用于调试）
sudo apt install -y net-tools iputils-ping
```

### 第二步：获取项目代码

```bash
# 进入项目目录
cd /home/lqd/ccg/vuln_scanner
```

### 第三步：创建虚拟环境（推荐）

```bash
# 创建虚拟环境
python3 -m venv venv

# 激活虚拟环境
source venv/bin/activate

# 确认 Python 版本
python --version  # 应显示 Python 3.10+
```

### 第四步：安装项目依赖

```bash
# 安装项目（开发模式）
pip install -e .

# 或者仅安装依赖
pip install -r requirements.txt
```

### 第五步：验证安装

```bash
# 检查 CLI 是否可用
python -m cli.main --help

# 检查 Nmap 是否安装
nmap --version
```

### 可选：配置 NVD API Key

NVD API 有请求频率限制，申请 API Key 可提高速率：

1. 访问 https://nvd.nist.gov/developers/request-an-api-key
2. 填写信息获取 API Key
3. 设置环境变量：

```bash
export NVD_API_KEY="your-api-key-here"
```

---

## 快速开始

### 命令行扫描

```bash
# 激活虚拟环境
source venv/bin/activate

# 执行扫描（需要 root 权限）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24

# 查看帮助
python -m cli.main --help
```

### Web 界面

```bash
# 启动 Web 服务器（需要 root 权限进行扫描）
sudo venv/bin/python -m web.app

# 访问浏览器
# http://127.0.0.1:5000
```

---

## 使用指南

### CLI 命令行界面

#### 基本扫描

```bash
# 扫描单个 IP
sudo venv/bin/python -m cli.main scan 192.168.1.1

# 扫描 IP 范围（CIDR）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24

# 扫描 IP 区间
sudo venv/bin/python -m cli.main scan 192.168.1.1-254
```

#### 扫描选项

```bash
# 指定发现方式
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method icmp   # ICMP Ping（默认）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method arp    # ARP 扫描（仅局域网）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method syn    # TCP SYN 扫描
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method all    # 全部方式

# 指定端口范围（用于 SYN 扫描）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --ports 1-65535

# 跳过服务识别
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --no-service

# 跳过漏洞匹配
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --no-vuln

# 启用主动漏洞验证（弱密码检测、SSL审计、NSE脚本）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --verify

# 指定报告输出路径
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --output /path/to/report.html

# 切换语言
sudo venv/bin/python -m cli.main --lang en_US scan 192.168.1.0/24
```

#### 查看历史

```bash
# 查看最近 10 条扫描记录
python -m cli.main history

# 查看最近 20 条
python -m cli.main history --limit 20
```

#### 生成报告

```bash
# 为已有扫描生成 HTML 报告
python -m cli.main report 1 --output scan_report.html

# 生成 PDF 报告
python -m cli.main report 1 --format pdf --output scan_report.pdf

# 生成 JSON 格式数据
python -m cli.main report 1 --format json --output scan_data.json
```

#### 扫描对比

```bash
# 对比两次扫描结果
python -m cli.main compare 1 2

# 输出：
# - 新增/消失的主机
# - 新增/消失的服务
# - 新增/修复的漏洞
# - 风险评分变化
```

#### 定时扫描

```bash
# 查看定时任务列表
python -m cli.main schedule list

# 添加定时任务（每天凌晨2点扫描）
sudo venv/bin/python -m cli.main schedule add \
    --name "每日内网扫描" \
    --target 192.168.1.0/24 \
    --cron "0 2 * * *"

# 添加每周一9点扫描
sudo venv/bin/python -m cli.main schedule add \
    --name "Weekly Scan" \
    --target 10.0.0.0/8 \
    --cron "0 9 * * 1" \
    --method all

# 启用/禁用任务
python -m cli.main schedule toggle 1

# 删除任务
python -m cli.main schedule remove 1

# 启动调度器（后台运行）
sudo venv/bin/python -m cli.main schedule start --daemon
```

#### NVD 数据管理

```bash
# 查看 NVD 缓存状态
python -m cli.main nvd status

# 自动同步（首次全量，之后增量）
python -m cli.main nvd sync

# 强制全量同步指定年份
python -m cli.main nvd sync --mode full --years 2020-2024

# 增量同步最近更新
python -m cli.main nvd sync --mode incremental

# 清空缓存
python -m cli.main nvd clear --confirm
```

#### 查看版本

```bash
python -m cli.main version
```

### Web 图形界面

#### 启动服务器

```bash
# 基本启动（仅本地访问）
sudo venv/bin/python -m web.app

# 允许局域网访问
sudo venv/bin/python -c "from web.app import run_server; run_server(host='0.0.0.0', port=5000)"

# 开启调试模式
sudo venv/bin/python -c "from web.app import run_server; run_server(debug=True)"
```

#### 页面功能

| 页面 | URL | 说明 |
|------|-----|------|
| 仪表盘 | `/` | 显示统计数据、最近扫描、安全态势趋势图、快速扫描表单 |
| 新建扫描 | `/scans/new` | 创建新的扫描任务 |
| 扫描详情 | `/scans/<id>` | 查看扫描结果、主机列表、漏洞详情、修复建议、验证结果 |
| 网络拓扑 | `/scans/<id>/topology` | 交互式网络拓扑可视化 |
| 扫描对比 | `/compare/<old>/<new>` | 对比两次扫描结果差异 |
| 历史记录 | `/history` | 查看所有扫描历史 |
| 定时任务 | `/schedules` | 管理定时扫描任务 |

#### 操作流程

1. **创建扫描**
   - 点击导航栏「新建扫描」或仪表盘右侧的快速扫描表单
   - 输入目标 IP/网段
   - 选择发现方式
   - 点击「开始扫描」

2. **查看结果**
   - 扫描完成后，点击「查看详情」进入详情页
   - 查看主机清单、风险评分、漏洞列表
   - 图表展示风险分布

3. **导出报告**
   - 在扫描详情页点击「导出报告」
   - 支持 HTML 和 PDF 格式下载

4. **对比扫描**
   - 在历史页面选择两次扫描进行对比
   - 查看主机、服务、漏洞的变化情况

5. **定时扫描**
   - 点击导航栏「定时任务」
   - 添加新任务，设置 Cron 表达式
   - 启动调度器后自动执行

---

## 高级功能

### 网络拓扑可视化

扫描完成后，可在扫描详情页点击「查看拓扑」按钮进入交互式网络拓扑图：

- **力导向布局**：自动排列主机节点
- **风险着色**：节点颜色映射风险等级（红色=高危、黄色=中危、绿色=低危）
- **交互操作**：点击节点查看主机详情，支持拖拽、缩放
- **子网分组**：同子网主机自动聚类显示

### 安全态势趋势仪表盘

仪表盘页面展示安全态势随时间的变化趋势：

- **漏洞数量趋势**：折线图展示历史扫描发现的漏洞数量变化
- **风险评分趋势**：跟踪整体安全态势改善或恶化
- **环比分析**：与上一扫描周期的对比指标

API 端点：
```bash
# 获取最近 30 天趋势数据
curl http://localhost:5000/api/trends?days=30
```

### 主动漏洞验证

使用 `--verify` 参数启用主动验证，从"可能存在"升级到"确认可利用"：

```bash
# 启用主动验证
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --verify
```

验证模块包括：

| 验证器 | 功能 | 检测项 |
|--------|------|--------|
| **NSE 脚本** | Nmap 漏洞脚本 | CVE 漏洞确认、服务配置缺陷 |
| **弱密码检测** | 常见服务凭据测试 | SSH/MySQL/Redis/FTP 弱密码 |
| **SSL/TLS 审计** | 证书与协议检查 | 证书过期、自签名、SSLv3/TLS1.0 |

**可选依赖**（启用完整验证功能）：
```bash
pip install paramiko pymysql
```

**安全说明**：弱密码检测仅测试 Top 10 常见弱密码，非暴力破解。密码信息在结果中已脱敏。

### 智能修复建议

扫描详情页为每个漏洞提供修复建议：

- **厂商公告**：从 NVD References 提取官方补丁链接
- **通用加固**：基于服务类型的安全配置建议（OpenSSH、Apache、MySQL 等）
- **优先级排序**：按 CVSS 评分 + 可利用性综合排序

API 端点：
```bash
# 获取扫描的修复建议
curl http://localhost:5000/api/scans/1/remediation
```

---

## 项目结构

```
vuln_scanner/
├── src/vulnscan/                 # 核心库
│   ├── __init__.py
│   ├── config.py                 # 配置管理
│   ├── core/                     # 核心模块
│   │   ├── __init__.py
│   │   ├── base.py               # 抽象基类定义
│   │   ├── models.py             # 数据模型
│   │   ├── scoring.py            # 风险评分算法
│   │   ├── pipeline.py           # 扫描流水线
│   │   └── diff.py               # 扫描对比算法
│   ├── scanners/                 # 扫描器实现
│   │   ├── __init__.py
│   │   ├── discovery/            # 主机发现
│   │   │   ├── __init__.py
│   │   │   ├── icmp.py           # ICMP Ping 扫描
│   │   │   ├── arp.py            # ARP 扫描
│   │   │   └── syn.py            # TCP SYN 扫描
│   │   └── service/              # 服务识别
│   │       ├── __init__.py
│   │       └── nmap.py           # Nmap 集成
│   ├── nvd/                      # NVD 漏洞库
│   │   ├── __init__.py
│   │   ├── client.py             # NVD API 客户端
│   │   ├── cache.py              # 本地缓存
│   │   ├── matcher.py            # 漏洞匹配引擎
│   │   ├── feeds.py              # 离线数据源解析
│   │   └── hybrid.py             # 混合同步协调器
│   ├── scheduler/                # 定时任务调度
│   │   ├── __init__.py
│   │   ├── jobs.py               # 任务模型与仓储
│   │   └── runner.py             # APScheduler 运行器
│   ├── storage/                  # 数据存储
│   │   ├── __init__.py
│   │   ├── database.py           # SQLite 数据库
│   │   ├── schema.py             # 表结构定义
│   │   └── repository.py         # 数据访问层
│   ├── reporting/                # 报告生成
│   │   ├── __init__.py
│   │   ├── generator.py          # HTML/PDF 报告生成器
│   │   └── charts.py             # ECharts 图表配置
│   └── i18n/                     # 国际化
│       ├── __init__.py
│       ├── zh_CN.py              # 中文
│       └── en_US.py              # 英文
├── cli/                          # 命令行界面
│   ├── __init__.py
│   └── main.py                   # Click CLI 入口
├── web/                          # Web 界面
│   ├── __init__.py
│   ├── app.py                    # Flask 应用工厂
│   ├── views.py                  # 视图路由
│   ├── api.py                    # REST API
│   ├── templates/                # Jinja2 模板
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── new_scan.html
│   │   ├── scan_detail.html
│   │   ├── history.html
│   │   ├── compare.html          # 扫描对比页
│   │   └── schedules.html        # 定时任务页
│   └── static/                   # 静态资源
│       ├── css/style.css
│       └── js/app.js
├── tests/                        # 测试用例
│   ├── __init__.py
│   ├── test_models.py
│   └── test_scoring.py
├── data/                         # 数据目录
│   ├── scanner.db                # SQLite 数据库
│   ├── nvd_cache/                # NVD 缓存
│   └── reports/                  # 生成的报告
├── docs/                         # 文档
│   └── NVD_DATA_SOURCE.md        # NVD 数据源说明
├── pyproject.toml                # 项目配置
├── requirements.txt              # 依赖清单
├── .gitignore                    # Git 忽略规则
└── README.md                     # 本文档
```

---

## 代码说明

### 核心模块 (src/vulnscan/core/)

#### models.py - 数据模型

定义系统中使用的所有数据结构：

```python
# 主机模型
@dataclass
class Host:
    ip: str                    # IP 地址
    hostname: str = None       # 主机名
    mac: str = None            # MAC 地址
    os_guess: str = None       # 操作系统猜测
    is_alive: bool = True      # 是否存活

# 服务模型
@dataclass
class Service:
    host_ip: str               # 所属主机 IP
    port: int                  # 端口号
    proto: str                 # 协议 (tcp/udp)
    service_name: str = None   # 服务名称
    product: str = None        # 产品名称
    version: str = None        # 版本号
    cpe: str = None            # CPE 标识
    state: PortState           # 端口状态

# 漏洞模型
@dataclass
class Vulnerability:
    cve_id: str                # CVE 编号
    cvss_base: float           # CVSS 基础分
    severity: Severity         # 严重程度
    description: str = None    # 漏洞描述

# 风险评估结果
@dataclass
class HostRiskResult:
    host_id: int               # 主机 ID
    risk_score: float          # 风险评分 (0-100)
    risk_level: RiskLevel      # 风险等级
    vuln_count: int            # 漏洞总数
    critical_count: int        # 严重漏洞数
    high_count: int            # 高危漏洞数
```

#### scoring.py - 风险评分算法

```python
class RiskScorer:
    """
    风险评分算法：
    1. 基于 CVSS 分数计算基础风险
    2. 根据漏洞严重程度加权
    3. 高危端口额外加权（如 SSH、RDP、SMB）
    4. 多漏洞累加时使用递减因子避免分数过高
    """

    def score_host(self, host, services, matches) -> HostRiskResult:
        # 计算每个漏洞的贡献分
        for match in matches:
            score = vuln.cvss_base * severity_weight * port_factor * confidence

        # 累加时使用递减因子
        total = sum(score * (0.8 ** i) for i, score in enumerate(sorted_scores))

        # 确定风险等级
        if score >= 70: return "Critical"
        elif score >= 40: return "High"
        elif score >= 20: return "Medium"
        else: return "Low"
```

#### pipeline.py - 扫描流水线

```python
class ScanPipelineRunner:
    """
    扫描流水线，按顺序执行：
    1. 主机发现 (0-30%)
    2. 服务识别 (30-60%)
    3. 漏洞匹配 (60-80%)
    4. 风险评估 (80-90%)
    5. 报告生成 (90-100%)
    """

    def run(self, target_range, ...) -> PipelineResult:
        # Stage 1: Host Discovery
        hosts = self._discover_hosts(target_range, method)

        # Stage 2: Service Identification
        services = self._scan_services(hosts)

        # Stage 3: Vulnerability Matching
        matches, vulns = self._match_vulnerabilities(services)

        # Stage 4: Risk Scoring
        risk_results = scorer.score_hosts(hosts, services, matches)

        # Stage 5: Report Generation
        report_generator.generate(...)
```

### 扫描器模块 (src/vulnscan/scanners/)

#### icmp.py - ICMP Ping 扫描

```python
class ICMPScanner(AssetScanner):
    """
    使用 Scapy 发送 ICMP Echo Request 探测存活主机
    - 优点：速度快，覆盖范围广
    - 缺点：可能被防火墙拦截
    """

    def _ping_host(self, ip: str) -> Host:
        packet = IP(dst=ip) / ICMP()
        reply = sr1(packet, timeout=self.timeout)
        if reply and reply.haslayer(ICMP):
            return Host(ip=ip, is_alive=True)
```

#### arp.py - ARP 扫描

```python
class ARPScanner(AssetScanner):
    """
    使用 ARP 协议发现局域网主机
    - 优点：不受防火墙影响，可获取 MAC 地址
    - 缺点：仅适用于同一广播域
    """

    def _arp_scan(self, ip: str) -> Host:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        result = srp(packet, timeout=self.timeout)
        # 返回包含 MAC 地址的 Host 对象
```

#### syn.py - TCP SYN 扫描

```python
class SYNScanner(AssetScanner):
    """
    TCP SYN 半开放扫描
    - 优点：可发现开放端口，更准确
    - 缺点：速度较慢
    """

    def _syn_scan(self, ip: str, port: int) -> bool:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        reply = sr1(packet, timeout=self.timeout)
        # SYN-ACK 表示端口开放
        return reply and reply.haslayer(TCP) and reply[TCP].flags == "SA"
```

#### nmap.py - Nmap 服务识别

```python
class NmapScanner(ServiceScanner):
    """
    调用 Nmap 进行服务版本检测
    - 获取服务名称、产品、版本
    - 获取 CPE 标识用于漏洞匹配
    - 可选：操作系统检测、NSE 脚本
    """

    def _scan_host(self, ip: str) -> ScanResult:
        self._nm.scan(hosts=ip, arguments="-sV --version-intensity 5")
        # 解析 Nmap 输出，提取服务信息
```

### NVD 模块 (src/vulnscan/nvd/)

#### client.py - NVD API 客户端

```python
class NVDClient:
    """
    NVD API 2.0 客户端
    - 支持 CPE 搜索和关键字搜索
    - 内置速率限制（无 Key: 0.6 req/s，有 Key: 5 req/s）
    """

    def search_by_cpe(self, cpe: str) -> List[Vulnerability]:
        url = f"{self.api_url}?cpeName={cpe}"
        response = self._request(url)
        return self._parse_vulnerabilities(response)
```

#### matcher.py - 漏洞匹配引擎

```python
class VulnerabilityMatcher:
    """
    漏洞匹配策略：
    1. CPE 精确匹配（置信度 0.95）
    2. CPE 部分匹配（置信度 0.70）
    3. 关键字搜索（置信度 0.50）
    """

    def match_service(self, service: Service) -> List[MatchResult]:
        # 优先使用 Nmap 返回的 CPE
        if service.cpe:
            return self._match_by_cpe(service, service.cpe)

        # 尝试构建 CPE
        guessed_cpe = self._guess_cpe(service)
        if guessed_cpe:
            return self._match_by_cpe(service, guessed_cpe, partial=True)

        # 降级为关键字搜索
        return self._match_by_keyword(service)
```

### 存储模块 (src/vulnscan/storage/)

#### schema.py - 数据库结构

```sql
-- 扫描任务表
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target_range TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    status TEXT DEFAULT 'pending'
);

-- 主机表
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    ip TEXT NOT NULL,
    hostname TEXT,
    mac TEXT,
    os_guess TEXT
);

-- 服务表
CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id),
    port INTEGER NOT NULL,
    proto TEXT DEFAULT 'tcp',
    service_name TEXT,
    product TEXT,
    version TEXT,
    cpe TEXT
);

-- 漏洞表
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    cvss_base REAL,
    severity TEXT,
    description TEXT
);

-- 风险评估结果表
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    host_id INTEGER REFERENCES hosts(id),
    risk_score REAL,
    risk_level TEXT,
    vuln_count INTEGER
);
```

### 报告模块 (src/vulnscan/reporting/)

#### generator.py - 报告生成器

```python
class ReportGenerator:
    """
    生成 HTML 格式的专业安全报告
    - Bootstrap 5 响应式布局
    - ECharts 交互式图表
    - 支持中英文切换
    - 支持打印优化
    """

    def generate(self, scan, hosts, services, vulnerabilities, risk_results):
        # 计算统计摘要
        summary = calculate_scan_risk_summary(risk_results)

        # 生成图表配置
        severity_chart = self.charts.severity_pie_chart(...)
        risk_chart = self.charts.risk_bar_chart(...)

        # 渲染 Jinja2 模板
        html = template.render(
            scan=scan,
            hosts=hosts,
            vulnerabilities=vulnerabilities,
            summary=summary,
            severity_chart_json=json.dumps(severity_chart),
            risk_chart_json=json.dumps(risk_chart),
        )
```

---

## API 文档

### REST API 端点

#### 获取扫描列表

```
GET /api/scans
```

响应示例：
```json
{
  "scans": [
    {
      "id": 1,
      "target_range": "192.168.1.0/24",
      "status": "completed",
      "started_at": "2024-01-15T10:30:00",
      "finished_at": "2024-01-15T10:35:00"
    }
  ]
}
```

#### 创建新扫描

```
POST /api/scans
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "method": "icmp",
  "ports": "1-1024"
}
```

响应示例：
```json
{
  "message": "Scan started",
  "target": "192.168.1.0/24",
  "method": "icmp"
}
```

#### 获取扫描详情

```
GET /api/scans/{scan_id}
```

响应示例：
```json
{
  "scan": {
    "id": 1,
    "target_range": "192.168.1.0/24",
    "status": "completed"
  },
  "hosts": [
    {
      "id": 1,
      "ip": "192.168.1.1",
      "hostname": "router",
      "services": [
        {"port": 22, "service_name": "ssh", "product": "OpenSSH", "version": "8.2"}
      ],
      "risk_score": 45.5,
      "risk_level": "High",
      "vuln_count": 3
    }
  ],
  "summary": {
    "total_hosts": 5,
    "total_vulns": 12,
    "critical_hosts": 1,
    "high_hosts": 2
  }
}
```

#### 获取扫描状态

```
GET /api/scans/{scan_id}/status
```

响应示例：
```json
{
  "id": 1,
  "status": "running",
  "finished_at": null
}
```

#### 下载报告

```
GET /api/scans/{scan_id}/report?format=html|pdf|json
```

| 参数 | 说明 |
|------|------|
| `format=html` | 下载 HTML 报告（默认） |
| `format=pdf` | 下载 PDF 报告 |
| `format=json` | 返回 JSON 数据 |

---

## Cron 表达式说明

定时扫描使用标准 5 字段 Cron 表达式：

```
┌───────────── 分钟 (0-59)
│ ┌───────────── 小时 (0-23)
│ │ ┌───────────── 日期 (1-31)
│ │ │ ┌───────────── 月份 (1-12)
│ │ │ │ ┌───────────── 星期 (0-6, 0=周日)
│ │ │ │ │
* * * * *
```

常用示例：

| 表达式 | 含义 |
|--------|------|
| `0 2 * * *` | 每天凌晨 2:00 |
| `0 */6 * * *` | 每 6 小时 |
| `30 9 * * 1-5` | 工作日 9:30 |
| `0 0 1 * *` | 每月 1 日 0:00 |
| `0 9 * * 1` | 每周一 9:00 |

---

## 常见问题

### Q1: 扫描时提示权限不足

**原因**：ICMP/ARP/SYN 扫描需要原始套接字权限。

**解决方案**：使用 sudo 运行：
```bash
sudo venv/bin/python -m cli.main scan 192.168.1.0/24
```

### Q2: Nmap 未找到

**原因**：系统未安装 Nmap。

**解决方案**：
```bash
sudo apt install -y nmap
```

### Q3: NVD API 请求过于频繁

**原因**：NVD API 有速率限制。

**解决方案**：
1. 申请免费 API Key：https://nvd.nist.gov/developers/request-an-api-key
2. 设置环境变量：`export NVD_API_KEY="your-key"`

### Q4: 扫描结果为空

**可能原因**：
1. 目标网络不可达
2. 防火墙拦截 ICMP
3. 目标主机关闭

**解决方案**：
1. 先用 `ping` 测试连通性
2. 尝试使用 `--method arp`（局域网）或 `--method syn`
3. 检查目标网络配置

### Q5: Web 界面无法访问

**解决方案**：
1. 确认服务器已启动：`sudo venv/bin/python -m web.app`
2. 检查端口是否被占用：`lsof -i :5000`
3. 如需局域网访问，使用 `host='0.0.0.0'`

### Q6: 数据库文件在哪里

**位置**：`data/scanner.db`

可通过环境变量自定义：
```bash
export VULNSCAN_DB_PATH="/custom/path/scanner.db"
```

### Q7: PDF 导出失败

**原因**：WeasyPrint 需要系统级依赖。

**解决方案**（Ubuntu/Debian）：
```bash
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2
```

### Q8: 定时任务不执行

**可能原因**：
1. 调度器未启动
2. 任务被禁用
3. Cron 表达式错误

**解决方案**：
1. 确认调度器运行：`python -m cli.main schedule start`
2. 检查任务状态：`python -m cli.main schedule list`
3. 验证 Cron 表达式格式

---

## 许可证

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
