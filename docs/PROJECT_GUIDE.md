# 项目指南（系统总览 / 论文友好版）

这份文档用于完整介绍项目“做什么、怎么做、边界在哪里”。  
如果你要写论文、做答辩、向别人介绍系统，优先看这份。

## 1. 项目定位

本项目是一个面向企业内部网络的脆弱性扫描与风险评估系统，目标是在授权范围内完成以下闭环：

```text
资产发现 → 服务识别 → 漏洞匹配 / 主动探测 → 风险量化 → 报告生成 → 入库与历史对比
```

当前产品形态已经收口为：

- Windows GUI 作为主控台
- Web 端只作为报告中心
- 本地规则库与本地实验靶场支撑离线演示

## 2. 当前版本的核心能力

### 2.1 资产发现

支持三种发现方式：

- `ICMP`
- `ARP`
- `SYN`

默认策略是递进式：

```text
ICMP -> ARP -> SYN
```

设计目的：

- 先用成本最低的方式做覆盖
- 再逐步补足被屏蔽或特殊环境中的主机

### 2.2 服务识别

分析模块优先调用：

```text
nmap -sV
```

并提供三种 GUI 预设：

- 快速扫描
- 标准扫描
- 深度扫描

### 2.3 漏洞匹配

当前漏洞来源有两类：

- 本地规则库匹配
  基于 `service / product / port / version_rule`
- 主动探测结果
  例如 `FTP anonymous`、`Redis 未授权`、`SNMP 默认 community`

此外，还支持少量弱口令尝试：

- `SSH`
- `FTP`
- `MySQL`

这些能力由 GUI 开关控制，可以明确决定是否参与最终评分。

### 2.4 风险量化

当前使用统一的可解释量化模型，对规则匹配结果与主动探测结果一视同仁。

核心因素包括：

- `CVSS`
- `AssetCriticality`
- `PortExposure`
- `ExploitMaturity`
- `MatchConfidence`

因此，主动探测命中的配置弱点也会进入总分，而不是单独旁路展示。

### 2.5 报告与对比

当前输出包括两类报告：

- 资产发现报告
- 分析报告

其中：

- 资产发现报告用于呈现主机发现结果
- 分析报告用于呈现服务、漏洞、风险评分与图表

历史对比默认只针对分析报告，重点回答：

- 新增了什么
- 修复了什么
- 哪些风险发生了升降

## 3. GUI 五页签职责

### 3.1 资产发现页

职责：

- 输入目标网段
- 选择扫描方式
- 生成资产发现报告
- 保存发现快照

边界：

- 不会自动触发漏洞匹配

### 3.2 漏洞匹配与服务识别页

职责：

- 独立输入目标网段
- 调用 `nmap` 做服务识别
- 结合规则库和主动探测形成分析结果
- 生成分析报告

边界：

- 不依赖第一页快照
- `nmap` 不可用时直接报错

### 3.3 规则库导入页

职责：

- 导入本地规则
- 选择合并或替换
- 查看规则摘要

扩展能力：

- 高级折叠区保留可信 URL 更新

### 3.4 报告对比页

职责：

- 选择两份分析报告
- 展示服务与风险差异
- 一键打开 Web 对比页

### 3.5 Web 报告中心页

职责：

- 启动 Web
- 打开 Web
- 停止 Web
- 查看和删除分析报告

## 4. 数据流与模块关系

### 4.1 主执行链路

```text
GUI / CLI
  ↓
Workbench
  ↓
ScanOrchestrator
  ↓
Discovery / Fingerprint / Match / ActiveChecks / RiskEvaluator
  ↓
HtmlReportGenerator + SQLite
```

### 4.2 数据存储

当前主要持久化对象：

- `data/scans.db`
  扫描历史、服务记录、漏洞记录
- `reports/<scan_name>/`
  HTML 报告与静态资源
- `data/discovery_sessions/`
  资产发现快照

## 5. 风险模型说明

当前评分公式：

```text
Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence
```

这个模型的意义不是“精确模拟真实攻击”，而是让输出具备：

- 可解释性
- 可排序性
- 可用于答辩展示的明确口径

### 5.1 置信度与人工确认

当前系统同时保留：

- `match_confidence`
- `confidence_tier`
- `manual_confirmation_needed`

当指纹信息不足，尤其是“版本缺失但规则要求版本比较”时，系统会主动降低置信度并提示人工确认，用来控制误报。

## 6. 资产画像

资产画像是一个额外输入，不是扫描器本身。

它的作用：

- 覆盖资产重要性
- 改变风险分和风险等级
- 在 GUI、报告、快照中体现“当前使用了哪份画像”

它不会改变：

- 主机是否在线
- 服务是否开放
- 指纹本身是否能识别成功

## 7. 主动探测与弱口令尝试

### 7.1 当前主动探测

默认可选能力包括：

- `FTP anonymous`
- `Redis 未授权`
- `Telnet 开放`
- `SNMP public/private`

### 7.2 当前少量弱口令尝试

可选能力包括：

- `SSH`
- `FTP`
- `MySQL`

设计约束：

- 字典很小，只做常见弱配置验证
- 默认关闭，由 GUI 明确控制
- 结果进入最终评分

## 8. 本地靶场与实验复现

项目内置了 Windows 友好的本地靶场，默认拓扑：

- `127.0.0.1:8080` -> `nginx`
- `127.0.0.2:2222` -> `OpenSSH`
- `127.0.0.3:2121` -> `FTP`
- `127.0.0.4:6379` -> `Redis`

这套靶场的主要用途：

- GUI 冒烟
- 论文截图
- 答辩演示
- 规则与主动探测验证

## 9. 当前限制

### 9.1 Windows 与网络环境限制

在 Windows 主控机上，ARP / SYN 受这些因素共同影响：

- `scapy` 与 Npcap
- 权限
- 代理与虚拟网卡
- 目标是否处于真实二层网络

因此系统设计为“自动降级继续”，而不是“任一步失败就整体不可用”。

### 9.2 回环靶场的边界

回环靶场适合验证：

- GUI 是否能跑通
- Web 是否能展示
- 规则与主动探测是否命中

它不适合验证：

- 真实 ARP 探测
- 真实局域网二层行为
- 面向公网的连通性

### 9.3 公网验证边界

项目不建议直接对第三方公网靶场发起扫描。  
如果要验证外网能力，应使用你自己控制的公网主机或云服务器，并遵守 [SECURITY_ETHICS.md](./SECURITY_ETHICS.md) 与 [external_validation_manual.md](./external_validation_manual.md)。

## 10. 推荐阅读顺序

1. [INSTALL.md](./INSTALL.md)
2. [usage_guide.md](./usage_guide.md)
3. [USER_MANUAL.md](./USER_MANUAL.md)
4. [demo_lab_guide.md](./demo_lab_guide.md)
5. [RULES_GUIDE.md](./RULES_GUIDE.md)
6. [test_report.md](./test_report.md)
