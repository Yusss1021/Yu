# 毕设分步实施手册

本手册直接对应你的任务书，可作为每周推进清单与论文写作依据。

配套阅读：

1. 实操手册：`docs/usage_guide.md`
2. 代码讲解：`docs/code_walkthrough.md`

## 第 1 阶段：需求固化与环境准备（第 1-2 周）

目标：

- 明确功能边界（资产发现、服务识别、漏洞匹配、风险评估、报告、历史对比）
- 完成开发环境初始化

动作：

1. 安装 Python 与虚拟环境
2. 安装依赖：`pip install -r requirements.txt`
3. 确认网络测试范围（只在授权内网执行）

产出：

- 可运行项目骨架

## 第 2 阶段：资产发现模块（第 5-6 周）

目标：

- 实现 ICMP/ARP/SYN 存活探测 + nmap 端口/服务识别

核心文件：

- `vuln_assessor/scanners/discovery.py`

验收：

- 对目标网段输出主机清单与开放端口

## 第 3 阶段：服务识别与漏洞匹配（第 7-8 周）

目标：

- 通过 Nmap 识别服务指纹
- 用本地规则库关联 CVE

核心文件：

- `vuln_assessor/scanners/service_fingerprint.py`
- `vuln_assessor/vuln/rules.json`
- `vuln_assessor/vuln/matcher.py`

验收：

- 每个漏洞条目包含：主机、端口、服务、版本、CVE、严重等级

## 第 4 阶段：风险评估与报告（第 9-10 周）

目标：

- 构建简化风险模型
- 输出可视化 HTML 报告

核心文件：

- `vuln_assessor/risk/evaluator.py`
- `vuln_assessor/report/generator.py`
- `vuln_assessor/report/templates/report.html.j2`

验收：

- 报告包含风险等级统计、Top 风险、资产明细

## 第 5 阶段：系统集成与数据管理（第 11-12 周）

目标：

- 完成 CLI 入口
- 实现 SQLite 结果存储与历史对比

核心文件：

- `vuln_assessor/cli.py`
- `vuln_assessor/storage/repository.py`
- `vuln_assessor/orchestrator.py`

验收：

- 支持 `scan` / `history` / `compare` 三个命令

## 第 6 阶段：测试与论文撰写（第 13-16 周）

目标：

- 完成系统测试、结果分析、论文定稿

建议测试维度：

1. 功能测试：各模块输入输出是否完整
2. 稳定性测试：异常网络环境下是否崩溃
3. 准确性测试：漏洞匹配误报/漏报率
4. 性能测试：不同网段规模下耗时

论文写作建议章节：

1. 绪论
2. 需求分析
3. 系统总体设计
4. 模块详细设计与实现
5. 系统测试与结果分析
6. 总结与展望
