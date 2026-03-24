# 面向企业内部网络的脆弱性扫描与风险评估系统设计与实现（半成稿）

> 说明：本文档已按你的项目现状填充主要内容，可直接作为毕业论文初稿。  
> 你只需补齐个人信息、学校格式要求、少量图表与文献页码。

---

## 封面信息（待填写）

- 题目：面向企业内部网络的脆弱性扫描与风险评估系统设计与实现
- 学生姓名：`【填写】`
- 学号：`【填写】`
- 学院：`【填写】`
- 专业：`【填写】`
- 指导教师：`【填写】`
- 完成时间：`【填写】`

---

## 中文摘要

针对企业内部网络中资产分散、漏洞信息离散、修复优先级难以确定等问题，本文设计并实现了一套内网脆弱性扫描与风险评估系统。系统采用模块化架构，围绕“资产发现、服务识别、漏洞匹配、风险量化、报告生成、历史对比与Web展示”构建完整流程，实现了从扫描到分析再到结果呈现的闭环。

在实现方面，系统使用 Python 作为主要开发语言，结合 Nmap、SQLite、Flask 与 Jinja2 完成工程化落地。服务识别采用“nmap高精度识别 + socket回退识别”双路径策略；漏洞匹配基于本地规则库，支持服务/产品/端口/版本规则联合约束；风险评估采用多因子量化模型，将 CVSS、资产重要性、端口暴露、可利用性与匹配置信度进行融合。

实验在可控靶场与真实运行环境中完成。结果表明：系统可稳定完成扫描、识别、匹配、评估和报告生成，支持并发任务与扫描结果差异分析；在资产画像参与下，风险分能够随业务场景变化而动态调整。整体上，系统满足本科毕业设计对功能完整性、可实现性、可验证性与可复现性的要求。

**关键词**：内网安全；漏洞扫描；风险评估；服务识别；毕业设计

---

## Abstract

This thesis presents the design and implementation of an internal-network vulnerability scanning and risk assessment system for enterprise environments. To address practical issues such as scattered assets, fragmented vulnerability information, and unclear remediation priorities, the system builds an end-to-end workflow including asset discovery, service fingerprinting, vulnerability matching, risk quantification, report generation, historical comparison, and web-based interaction.

The implementation is based on Python, with Nmap, SQLite, Flask, and Jinja2. A dual-path service identification strategy is adopted: high-accuracy Nmap-based detection and socket-based fallback detection. Vulnerability matching is rule-driven and supports combined constraints over service, product, port, and version expressions. A multi-factor risk model is used to integrate CVSS, asset criticality, port exposure, exploit maturity, and match confidence.

Experiments in both controlled lab and real runtime environments show that the system can stably complete the full pipeline and supports concurrent tasks and differential analysis between scan rounds. Results also verify that risk scores can dynamically change with asset profiles. The system meets the expected requirements of an undergraduate graduation project in terms of completeness, implementability, verifiability, and reproducibility.

**Keywords**: intranet security; vulnerability scanning; risk assessment; service fingerprinting

---

## 第1章 绪论

### 1.1 研究背景

随着企业数字化建设推进，内部网络规模不断扩大，资产类型与服务种类持续增加。传统依赖人工台账与零散工具的方式，难以持续掌握资产暴露面与漏洞风险状态。在实际运维中，常见问题包括：资产发现不全面、服务版本识别不稳定、漏洞结果无法排序、修复优先级不明确等。

因此，构建一套可持续运行、可量化评估、可历史追踪的内网脆弱性扫描系统，具有明显工程价值和应用意义。

### 1.2 研究意义

1. **工程意义**：建立统一流程，降低安全排查的人力成本。  
2. **管理意义**：通过风险分级支持修复优先级决策。  
3. **教学意义**：形成可复现实验平台，满足本科毕设“可实现+可验证”要求。

### 1.3 研究目标与内容

本文围绕以下目标展开：

1. 实现资产发现与端口探测；
2. 实现服务识别与版本提取；
3. 实现规则驱动的漏洞匹配；
4. 构建可解释的风险量化模型；
5. 输出可视化报告并支持历史对比；
6. 提供 Web 界面与并发任务能力。

### 1.4 论文结构

- 第1章：绪论  
- 第2章：相关技术与理论基础  
- 第3章：需求分析与总体设计  
- 第4章：系统详细设计与实现  
- 第5章：系统测试、量化评估与合规分析  
- 第6章：总结与展望

---

## 第2章 相关技术与理论基础

### 2.1 资产发现技术

资产发现主要依赖 ICMP、ARP 和 TCP 探测。ICMP 可用于主机存活判断；ARP 适用于同网段二层发现；TCP 连接探测可用于开放端口识别。本文在工程中组合三种方式，并通过线程池并发提升扫描效率。

### 2.2 服务识别技术

服务识别核心在于对开放端口进行应用层指纹判断。Nmap 的 `-sV` 能提供较高识别精度，但存在环境依赖。本文采用“双路径”策略：优先使用 Nmap，未安装时回退为 socket/banner 识别，保证可用性。

### 2.3 漏洞匹配机制

漏洞匹配采用本地规则库，规则包含 `cve_id、service、product、version_rule、cvss` 等字段。匹配过程包括服务/产品匹配与版本规则匹配两阶段，版本规则支持比较符与区间表达。

### 2.4 风险量化方法

为解决“漏洞多但优先级不清晰”的问题，本文采用多因子线性加权模型，融合漏洞严重度与业务语境信息，输出统一风险分与风险等级，提升结果可执行性。

---

## 第3章 需求分析与总体设计

### 3.1 功能需求

1. 资产发现：识别目标网段可达主机与开放端口；  
2. 服务识别：输出服务名、产品名、版本信息；  
3. 漏洞匹配：根据规则库输出命中漏洞；  
4. 风险评估：对漏洞进行量化打分与分级；  
5. 报告输出：生成 HTML 报告；  
6. 历史对比：支持两次扫描差异分析；  
7. Web使用：支持任务提交、状态查看、详情与对比。

### 3.2 非功能需求

1. 可用性：异常输入不崩溃，提供可读错误提示；  
2. 可扩展性：规则库可导入、可更新；  
3. 并发能力：支持任务级并发；  
4. 可复现性：支持本地靶场稳定复现实验。

### 3.3 系统总体架构

系统采用“入口层 + 编排层 + 功能层 + 数据层”结构：

- 入口层：CLI 与 Web；
- 编排层：Orchestrator 统一流程调度；
- 功能层：Discovery / Fingerprint / Matcher / Risk / Report；
- 数据层：SQLite Repository 持久化与差异计算。

### 3.4 数据库设计

系统核心数据表如下：

1. `scans`：扫描任务元数据与统计；  
2. `assets`：资产发现结果；  
3. `services`：服务识别结果；  
4. `vulnerabilities`：漏洞与风险评估结果。

---

## 第4章 系统详细设计与实现

### 4.1 模块实现映射

- 资产发现：`vuln_assessor/scanners/discovery.py`
- 服务识别：`vuln_assessor/scanners/service_fingerprint.py`
- 漏洞匹配：`vuln_assessor/vuln/matcher.py`
- 风险评估：`vuln_assessor/risk/evaluator.py`
- 报告生成：`vuln_assessor/report/generator.py`
- 数据存储与对比：`vuln_assessor/storage/repository.py`
- Web 与并发任务：`vuln_assessor/webapp.py`

### 4.2 关键实现说明

1. **发现模块**：支持 `icmp/arp/syn` 组合，按 `icmp -> arp -> syn` 逐层补充；`syn` 用于发现仅开放端口的主机（需 root）。  
2. **识别模块**：优先 nmap 识别，失败自动回退 socket。  
3. **匹配模块**：多条件规则匹配，支持版本区间与比较符。  
4. **评估模块**：采用可解释多因子风险公式。  
5. **对比模块**：支持服务差异、漏洞差异、持续漏洞风险变化。  
6. **Web模块**：支持后台任务队列、任务状态查询、结果可视化。

### 4.3 风险模型

本文风险评分模型为：

`Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence`

风险分级策略：

- `score >= 8.0`：HIGH  
- `5.0 <= score < 8.0`：MEDIUM  
- `< 5.0`：LOW

---

## 第5章 系统测试、量化评估与合规分析

> 本章已形成完整可粘贴版本：`docs/thesis_chapter5_paste_ready.md`。  
> 这里给出核心结论摘要，可直接纳入正文。

### 5.1 测试环境

- Python：3.10.12  
- SQLite：3.37.2  
- Nmap：7.80  
- 平台：Linux（WSL2）

### 5.2 量化结果摘要

1. 命令级测试通过率：15/15，100%；  
2. 风险模型前后对比（ID=25 vs 26）：  
   - CVE-2021-41617：7.68 -> 7.48（-0.20）  
   - CVE-2021-32626：7.53 -> 7.23（-0.30）  
3. Web并发：提交5任务全部完成；  
4. 真实环境：本机真实服务端口可识别，并可通过 compare 检出新增服务。

### 5.3 局限性与合规

局限性：

1. 规则库规模仍有扩展空间；  
2. 服务版本识别受目标响应质量影响；  
3. 资产画像目前以人工维护为主。

合规要求：

1. 仅在授权网络执行扫描；  
2. 禁止对未授权目标实施探测；  
3. 扫描结果仅用于教学与防护研究。

### 5.4 可复现实验流程

说明：端口与服务识别由 `nmap -sV` 阶段完成，`syn` 用于主机存活补充。

1. 启动靶场：`./lab/start_demo_lab.sh`  
2. 扫描（无画像）：`python3 main.py scan --target 127.0.0.1/32 --methods icmp,syn --ports 2222,6379 --name exp_no_profile`  
3. 扫描（有画像）：`python3 main.py scan --target 127.0.0.1/32 --methods icmp,syn --ports 2222,6379 --asset-profile docs/asset_profile.example.json --name exp_with_profile`  
4. 对比：`python3 main.py compare --base <ID_A> --new <ID_B>`  
5. 停止靶场：`./lab/stop_demo_lab.sh`

---

## 第6章 总结与展望

### 6.1 工作总结

本文完成了一个面向企业内网的脆弱性扫描与风险评估原型系统，实现了从发现到评估再到对比的完整流程，并通过真实环境与可控靶场验证了系统可用性与稳定性。

### 6.2 主要贡献

1. 构建了可落地的端到端安全评估闭环；  
2. 实现了多因子风险量化模型并完成对比验证；  
3. 提供了 Web 并发任务与结果对比能力；  
4. 形成了完整文档体系与可复现实验方案。

### 6.3 后续展望

1. 扩展规则库来源并增强清洗标准化能力；  
2. 引入更丰富的风险因子（拓扑、攻击路径、业务依赖）；  
3. 增加自动化测试框架与持续集成流程；  
4. 支持更高并发与更大规模网络部署。

---

## 参考文献（示例）

[1] FIRST. Common Vulnerability Scoring System v3.1 Specification[EB/OL].  
[2] Nmap Project. Nmap Reference Guide[EB/OL].  
[3] Scapy Documentation[EB/OL].  
[4] OWASP. Vulnerability Management Guide[EB/OL].  
[5] 【补充学校要求数量的期刊/会议文献】。

---

## 致谢（模板）

感谢指导教师【姓名】在选题、设计与论文撰写过程中给予的指导；感谢同学与实验环境支持人员在测试与数据整理方面提供的帮助。
