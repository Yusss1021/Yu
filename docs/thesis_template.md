# 本科毕业论文模板（面向企业内部网络的脆弱性扫描与风险评估系统）

> 使用方式：将 `【】` 内内容替换为你的实际信息；保留章节结构，按学校格式要求调整字体、行距、页边距与编号。

---

## 题目页

题目：`【面向企业内部网络的脆弱性扫描与风险评估系统的设计与实现】`  
学生姓名：`【姓名】`  
学号：`【学号】`  
学院：`【学院】`  
专业：`【专业】`  
指导教师：`【导师姓名】`  
完成日期：`【YYYY年MM月】`

---

## 中文摘要

本文针对【企业内网资产分散、漏洞优先级不明确】问题，设计并实现了一套【内网脆弱性扫描与风险评估系统】。系统围绕“资产发现—服务识别—漏洞匹配—风险量化—报告生成—历史对比”构建完整流程。  
在实现上，采用【Python + SQLite + Nmap + Flask】技术栈；在评估上，提出了融合 `CVSS`、资产重要性、端口暴露、可利用性和匹配置信度的风险量化模型。  
实验结果表明：系统能够在【真实环境与可控靶场】中稳定完成扫描、识别与评估任务，并支持并发任务与结果差异分析，满足本科毕业设计的功能与工作量要求。  

关键词：`【内网安全】`；`【漏洞扫描】`；`【风险评估】`；`【服务识别】`；`【毕业设计】`

---

## Abstract

This thesis designs and implements an internal-network vulnerability scanning and risk assessment system to address the issues of scattered assets and unclear remediation priorities in enterprise intranets.  
The system provides an end-to-end workflow including asset discovery, service fingerprinting, vulnerability matching, risk quantification, report generation, and historical comparison.  
The implementation is based on 【Python, SQLite, Nmap, Flask】. A multi-factor risk model is adopted by combining CVSS, asset criticality, port exposure, exploit maturity, and match confidence.  
Experimental results in both real and controlled environments show that the system works stably and supports concurrent scanning tasks and differential analysis, meeting the requirements of an undergraduate graduation project.  

Key words: `【intranet security】`, `【vulnerability scanning】`, `【risk assessment】`, `【service fingerprinting】`

---

## 目录

（自动生成）

---

## 第1章 绪论

### 1.1 研究背景与意义
- 【行业背景】
- 【现有问题】
- 【本课题意义】

### 1.2 国内外研究现状
- 【国外研究进展】
- 【国内研究进展】
- 【现有方案不足】

### 1.3 研究内容与目标
- 【目标1】
- 【目标2】
- 【目标3】

### 1.4 论文结构安排
- 第1章……
- 第2章……

---

## 第2章 相关技术与理论基础

### 2.1 网络资产发现技术
### 2.2 服务识别与版本指纹技术
### 2.3 漏洞规则匹配机制
### 2.4 风险量化评估方法
### 2.5 本章小结

---

## 第3章 需求分析与总体设计

### 3.1 需求分析
#### 3.1.1 功能需求
- 资产发现
- 服务识别
- 漏洞匹配
- 风险评估
- 报告与历史对比

#### 3.1.2 非功能需求
- 可用性
- 可扩展性
- 并发能力
- 合规性

### 3.2 系统总体架构
- 【架构图】
- 【模块关系说明】

### 3.3 数据库设计
- 表结构说明：`scans / assets / services / vulnerabilities`
- 【ER图或关系说明】

### 3.4 本章小结

---

## 第4章 系统详细设计与实现

### 4.1 系统实现架构
- 入口层（CLI/Web）
- 编排层（Orchestrator）
- 功能层（Scanners/Vuln/Risk/Report）
- 数据层（Repository）

### 4.2 资产发现模块实现
- 实现文件：`vuln_assessor/scanners/discovery.py`
- 核心流程与关键算法说明

### 4.3 服务识别模块实现
- 实现文件：`vuln_assessor/scanners/service_fingerprint.py`
- `nmap` 主路径与 fallback 机制

### 4.4 漏洞匹配模块实现
- 实现文件：`vuln_assessor/vuln/matcher.py`
- 版本规则解析与匹配逻辑

### 4.5 风险评估模块实现
- 实现文件：`vuln_assessor/risk/evaluator.py`
- 风险模型公式与分级策略

### 4.6 报告与存储模块实现
- 实现文件：`vuln_assessor/report/generator.py`
- 实现文件：`vuln_assessor/storage/repository.py`

### 4.7 Web与并发任务实现
- 实现文件：`vuln_assessor/webapp.py`
- 任务状态流转与并发参数

### 4.8 本章小结

---

## 第5章 系统测试与结果分析

> 可直接参考：`docs/thesis_chapter5_paste_ready.md`

### 5.1 测试环境
- 硬件/软件环境表

### 5.2 测试方案与用例
- 功能测试
- 异常测试
- 并发测试
- 真实环境测试

### 5.3 测试结果
#### 5.3.1 功能通过率
| 指标 | 数值 |
|---|---:|
| 测试项总数 | 【】 |
| 通过数 | 【】 |
| 失败数 | 【】 |
| 通过率 | 【】 |

#### 5.3.2 风险模型对比结果
| CVE | 端口 | 风险分(基线) | 风险分(改进) | 变化量 | 结论 |
|---|---:|---:|---:|---:|---|
| 【】 | 【】 | 【】 | 【】 | 【】 | 【】 |

### 5.4 局限性与合规分析
- 系统局限性
- 合规边界
- 工程风险控制

### 5.5 本章小结

---

## 第6章 总结与展望

### 6.1 工作总结
- 完成了【】
- 实现了【】
- 验证了【】

### 6.2 创新点与贡献
- 【贡献1】
- 【贡献2】

### 6.3 后续工作展望
- 规则库扩展
- 模型优化
- 工程化部署与告警联动

---

## 参考文献（示例格式）

[1] 【作者】. 【题目】[J]. 【期刊】, 【年份】, 【卷(期)】: 【页码】.  
[2] 【作者】. 【题目】[M]. 【出版社】, 【年份】.  
[3] 【Author】. 【Title】[C]. 【Conference】, 【Year】: 【Pages】.  
[4] Nmap Project. Nmap Reference Guide[EB/OL]. https://nmap.org/book/man.html.  
[5] FIRST. CVSS v3.1 Specification[EB/OL]. https://www.first.org/cvss/specification-document.

---

## 致谢

感谢【导师姓名】老师在课题选题、系统设计与论文撰写过程中给予的指导；感谢【同学/实验室】在测试与数据整理中的帮助。

---

## 附录（可选）

### 附录A 关键命令清单
```bash
python3 main.py scan --target 127.0.0.1/32 --methods icmp,arp,syn --ports 2222,6379
python3 main.py history --limit 10
python3 main.py compare --base 1 --new 2
python3 main.py web --host 127.0.0.1 --port 5000 --max-concurrent 3
```

### 附录B 主要代码文件映射
- `vuln_assessor/scanners/discovery.py`
- `vuln_assessor/scanners/service_fingerprint.py`
- `vuln_assessor/vuln/matcher.py`
- `vuln_assessor/risk/evaluator.py`
- `vuln_assessor/storage/repository.py`
- `vuln_assessor/webapp.py`
