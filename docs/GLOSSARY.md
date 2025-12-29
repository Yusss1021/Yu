# 术语表

> VulnScanner 项目相关术语解释

---

## 网络安全术语

| 术语 | 英文 | 含义 |
|------|------|------|
| **CVE** | Common Vulnerabilities and Exposures | 通用漏洞披露。标准化的漏洞编号系统，如 CVE-2021-44228 |
| **CVSS** | Common Vulnerability Scoring System | 通用漏洞评分系统。评估漏洞严重程度的标准，范围 0-10 |
| **CPE** | Common Platform Enumeration | 通用平台枚举。标识软件/硬件的标准格式，如 `cpe:2.3:a:apache:http_server:2.4.41` |
| **NVD** | National Vulnerability Database | 国家漏洞数据库。美国 NIST 维护的漏洞信息库 |
| **OWASP** | Open Web Application Security Project | 开放式 Web 应用程序安全项目。提供 Web 安全最佳实践 |
| **漏洞** | Vulnerability | 系统中可被利用的安全缺陷 |
| **漏洞利用** | Exploit | 利用漏洞进行攻击的代码或方法 |
| **渗透测试** | Penetration Testing (Pentest) | 模拟黑客攻击以发现安全漏洞的测试方法 |
| **主动验证** | Active Verification | 实际尝试利用或探测目标以确认漏洞存在 |
| **被动匹配** | Passive Matching | 基于版本号等信息匹配已知漏洞，不实际探测 |

---

## 网络扫描术语

| 术语 | 英文 | 含义 |
|------|------|------|
| **主机发现** | Host Discovery | 识别网络中存活主机的过程 |
| **服务识别** | Service Detection | 识别主机上运行的服务及其版本 |
| **端口扫描** | Port Scanning | 探测目标主机开放端口的过程 |
| **ICMP** | Internet Control Message Protocol | 互联网控制消息协议，Ping 命令使用此协议 |
| **ARP** | Address Resolution Protocol | 地址解析协议，用于 IP 到 MAC 地址映射 |
| **SYN 扫描** | SYN Scan | 半开放端口扫描，发送 SYN 包但不完成握手 |
| **Banner** | Banner | 服务返回的标识信息，通常包含产品和版本 |
| **指纹识别** | Fingerprinting | 通过特征识别操作系统或服务类型 |
| **CIDR** | Classless Inter-Domain Routing | 无类别域间路由，如 192.168.1.0/24 表示 256 个 IP |
| **子网** | Subnet | 将大网络划分为更小的网络段 |

---

## 风险评估术语

| 术语 | 英文 | 含义 |
|------|------|------|
| **风险评分** | Risk Score | 本项目中用于量化主机安全风险的评分（0-100） |
| **风险等级** | Risk Level | 基于评分划分的等级：Critical/High/Medium/Low/Info |
| **严重程度** | Severity | 漏洞的严重程度：Critical/High/Medium/Low |
| **置信度** | Confidence | 漏洞匹配的可信程度（0-1） |
| **暴露系数** | Exposure Factor | 端口暴露程度对风险的影响因子 |
| **高危端口** | High-Risk Ports | 常被攻击的端口，如 22(SSH)、3389(RDP) |

---

## 项目架构术语

| 术语 | 英文 | 含义 |
|------|------|------|
| **扫描流水线** | Scan Pipeline | 扫描任务的多阶段处理流程 |
| **扫描器** | Scanner | 执行主机发现或服务识别的组件 |
| **验证器** | Verifier | 执行主动安全检测的组件 |
| **仓储模式** | Repository Pattern | 数据访问层的设计模式，封装数据库操作 |
| **上下文** | Context | 在流水线阶段间传递的数据容器 |
| **蓝图** | Blueprint | Flask 框架中组织路由的模块化机制 |

---

## 常见漏洞类型

| 术语 | 英文 | 含义 |
|------|------|------|
| **弱密码** | Weak Password | 容易被猜测或暴力破解的密码 |
| **未授权访问** | Unauthorized Access | 无需认证即可访问敏感资源 |
| **远程代码执行** | Remote Code Execution (RCE) | 攻击者可在目标系统上执行任意代码 |
| **SQL 注入** | SQL Injection | 通过输入恶意 SQL 语句攻击数据库 |
| **XSS** | Cross-Site Scripting | 跨站脚本攻击，在页面中注入恶意脚本 |
| **点击劫持** | Clickjacking | 诱骗用户点击隐藏的恶意链接 |
| **中间人攻击** | Man-in-the-Middle (MITM) | 攻击者拦截并可能篡改通信内容 |
| **目录遍历** | Path Traversal | 通过 `../` 等访问非授权文件 |

---

## 常见服务与协议

| 术语 | 端口 | 含义 |
|------|------|------|
| **SSH** | 22 | 安全外壳协议，用于远程登录 |
| **HTTP** | 80 | 超文本传输协议，Web 服务 |
| **HTTPS** | 443 | 加密的 HTTP 协议 |
| **FTP** | 21 | 文件传输协议 |
| **MySQL** | 3306 | MySQL 数据库服务 |
| **Redis** | 6379 | Redis 内存数据库 |
| **SMB** | 445 | 服务器消息块协议，Windows 文件共享 |
| **RDP** | 3389 | 远程桌面协议 |
| **SMTP** | 25 | 简单邮件传输协议 |
| **DNS** | 53 | 域名系统服务 |

---

## 知名漏洞代号

| 代号 | CVE | 含义 |
|------|-----|------|
| **Log4Shell** | CVE-2021-44228 | Log4j 远程代码执行漏洞 |
| **EternalBlue** | CVE-2017-0144 | Windows SMB 远程代码执行，WannaCry 使用 |
| **Heartbleed** | CVE-2014-0160 | OpenSSL 内存泄露漏洞 |
| **Shellshock** | CVE-2014-6271 | Bash 远程代码执行漏洞 |
| **POODLE** | CVE-2014-3566 | SSLv3 协议漏洞 |

---

## 工具与框架

| 术语 | 含义 |
|------|------|
| **Nmap** | 网络扫描和安全审计工具 |
| **NSE** | Nmap Scripting Engine，Nmap 脚本引擎 |
| **Scapy** | Python 网络包构造和解析库 |
| **Flask** | Python 轻量级 Web 框架 |
| **SQLite** | 嵌入式关系型数据库 |
| **ECharts** | 百度开源的 JavaScript 图表库 |
| **WeasyPrint** | HTML 到 PDF 转换库 |
| **Click** | Python 命令行接口框架 |

---

## 报告相关术语

| 术语 | 英文 | 含义 |
|------|------|------|
| **扫描摘要** | Scan Summary | 扫描结果的概览信息 |
| **风险分布** | Risk Distribution | 各风险等级的统计分布 |
| **修复建议** | Remediation | 针对发现问题的修复指导 |
| **拓扑图** | Topology | 网络结构的可视化图形 |
| **趋势分析** | Trend Analysis | 安全状态随时间的变化趋势 |

---

## 缩写对照

| 缩写 | 全称 | 中文 |
|------|------|------|
| API | Application Programming Interface | 应用程序接口 |
| CLI | Command Line Interface | 命令行接口 |
| CRUD | Create, Read, Update, Delete | 增删改查 |
| ER | Entity-Relationship | 实体关系 |
| IP | Internet Protocol | 互联网协议 |
| JSON | JavaScript Object Notation | JavaScript 对象表示法 |
| MAC | Media Access Control | 媒体访问控制（地址） |
| OS | Operating System | 操作系统 |
| REST | Representational State Transfer | 表述性状态转移 |
| SSL | Secure Sockets Layer | 安全套接层 |
| TCP | Transmission Control Protocol | 传输控制协议 |
| TLS | Transport Layer Security | 传输层安全 |
| UDP | User Datagram Protocol | 用户数据报协议 |
| URL | Uniform Resource Locator | 统一资源定位符 |

---

## 项目特定术语

| 术语 | 含义 |
|------|------|
| **ScanPipelineRunner** | 扫描流水线运行器，协调整个扫描过程 |
| **ScanContext** | 扫描上下文，在流水线阶段间传递数据 |
| **HostRiskResult** | 主机风险评估结果 |
| **VerificationResult** | 主动验证结果 |
| **ServiceVuln** | 服务与漏洞的关联记录 |
| **CVECache** | CVE 本地缓存 |
| **VulnerabilityMatcher** | 漏洞匹配器 |
| **RemediationEngine** | 修复建议引擎 |
| **ReportGenerator** | 报告生成器 |
| **ChartGenerator** | 图表生成器 |

---

## 下一步

- [系统架构](ARCHITECTURE.md) - 了解整体架构设计
- [快速上手](tutorials/quick_start.md) - 开始使用 VulnScanner
- [核心模块](modules/01_core.md) - 深入了解核心实现
