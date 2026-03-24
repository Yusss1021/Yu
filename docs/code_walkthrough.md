# 核心代码讲解（按执行链路）

本文件用于帮助你“读懂项目”，建议和 `docs/usage_guide.md` 配合阅读。

## 1. 总体调用链路

从命令行执行一次扫描时，链路是：

1. `main.py` 入口调用 `vuln_assessor/cli.py`
2. `handle_scan()` 解析参数并创建 `ScanOrchestrator`
3. `ScanOrchestrator.run_scan()` 依次执行：
   - 资产发现 `AssetDiscoveryEngine`
   - 服务识别 `ServiceFingerprintEngine`
   - 漏洞匹配 `VulnerabilityMatcher`
   - 风险评估 `RiskEvaluator`
   - 报告生成 `HtmlReportGenerator`
   - 结果持久化 `ScanRepository`

这是最重要的主流程，代码位置：

- `vuln_assessor/cli.py`
- `vuln_assessor/orchestrator.py`

---

## 2. 参数解析与输入校验

关键文件：`vuln_assessor/config.py`

## 2.1 `parse_ports()`

作用：

1. 支持 `22,80,443` 形式
2. 支持 `1-1024` 范围形式
3. 严格校验非法端口并报错

设计意图：

- 避免错误输入触发 Python Traceback，改为可读错误提示。

## 2.2 `parse_methods()`

作用：

1. 只允许 `icmp/arp/syn`
2. 对非法方法名直接报错

设计意图：

- 避免输入拼写错误后系统静默使用默认值，提升实验可控性。

---

## 3. 扫描编排核心

关键文件：`vuln_assessor/orchestrator.py`

## 3.1 `run_scan()` 做了什么

顺序非常固定：

1. 记录开始时间
2. `discover()` 找存活主机与 MAC 信息（按 ICMP -> ARP -> SYN 逐层补充）
3. `fingerprint()` 识别服务和版本
4. `match()` 从规则库映射漏洞
5. `evaluate()` 做风险量化
6. `generate()` 生成 HTML 报告
7. `save_scan()` 入库
8. 汇总 high/medium/low 返回到 CLI/Web

这段是论文里“系统时序图”的直接代码依据。

---

## 4. 模块说明

## 4.1 资产发现模块

文件：`vuln_assessor/scanners/discovery.py`

核心点：

1. ICMP：调用 `ping` 并发探测
2. ARP：使用 `scapy`（需 root）
3. SYN：半开探测发现仅开放端口的主机（需 root）
4. SYN 仅对未被 ICMP/ARP 发现的主机执行，减少噪声
5. 内部线程池并发执行主机扫描

## 4.2 服务识别模块

文件：`vuln_assessor/scanners/service_fingerprint.py`

策略：

1. 优先 `nmap -sV` 输出 XML 并解析产品/版本，同时完成端口探测
2. 未安装 `nmap` 时回退 socket + 常见端口映射
3. 最终按 `(host_ip, port, protocol)` 去重

## 4.3 漏洞匹配模块

文件：`vuln_assessor/vuln/matcher.py`

重点逻辑：

1. 规则匹配维度：`service/product/port/version_rule`
2. 版本规则支持：
   - 比较符：`< <= > >= ==`
   - 区间：`x.y-z.w`
3. 输出匹配置信度 `match_confidence`（0-10）

## 4.4 风险评估模块

文件：`vuln_assessor/risk/evaluator.py`

公式（v2）：

`Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence`

补充逻辑：

1. 支持资产画像覆盖 `asset_criticality`
2. 若规则未给 exploit 值，按 severity 映射默认值
3. 输出等级阈值：`HIGH >= 8`，`MEDIUM >= 5`

## 4.5 报告模块

文件：`vuln_assessor/report/generator.py`

关键点：

1. Jinja2 渲染 HTML 报告
2. 生成风险分布图数据
3. 报告名做安全规范化，避免路径穿越

## 4.6 存储与对比模块

文件：`vuln_assessor/storage/repository.py`

关键点：

1. SQLite 存储 `scans/assets/services/vulnerabilities`
2. 对比输出支持服务与漏洞双维度
3. 持续漏洞会输出风险变化字段
4. 对比前先校验扫描 ID 是否存在

并发稳定性：

1. `PRAGMA journal_mode=WAL`
2. `busy_timeout` + 连接超时，减少并发写锁报错

---

## 5. Web 端执行链路

关键文件：`vuln_assessor/webapp.py`

## 5.1 并发任务管理

`ConcurrentScanTaskManager` 用 `ThreadPoolExecutor` 管理后台扫描任务：

1. `submit_scan()` 入队并返回任务 ID
2. `_run_scan_task()` 调用同一套 `ScanOrchestrator` 流程
3. 任务状态：`queued/running/finished/failed`

## 5.2 页面与接口

1. `/`：仪表盘 + 任务提交
2. `/scan/<id>`：扫描详情
3. `/compare`：服务与漏洞差异对比
4. `/task/<task_id>`：任务状态 JSON
5. `/report/<scan_id>`：HTML 报告内容

---

## 6. 本轮修复的关键问题

1. **参数异常崩溃**：`--ports abc` 会报 Traceback  
   - 修复：配置层严格校验 + CLI 友好错误提示
2. **对比误用问题**：不存在扫描 ID 被当成空基线  
   - 修复：对比前强校验扫描 ID
3. **报告命名风险**：`--name` 可包含路径字符  
   - 修复：报告名安全规范化
4. **并发写库稳定性**：并发任务下可能出现锁等待  
   - 修复：SQLite 连接超时 + WAL + busy_timeout

---

## 7. 你答辩时可重点讲的代码点

1. `orchestrator.run_scan()`：完整流程总控
2. `matcher._version_matches()`：版本规则解析与比较
3. `evaluator._calculate_score()`：风险量化核心
4. `repository.compare_scan_outputs()`：结果差异分析
5. `webapp.ConcurrentScanTaskManager`：并发任务调度
