# 面向企业内部网络的脆弱性扫描与风险评估系统（本科毕设原型）

本项目基于你的开题报告与任务书，提供一个可直接运行的 MVP 原型，覆盖以下链路：

1. 资产探测与发现（`icmp` / `arp` / `syn`，按优先级依次探测）
2. 服务识别与版本指纹（优先使用 `nmap -sV`）
3. 本地漏洞规则库匹配（`CVE + 版本规则`）
4. 风险量化评估（高/中/低）
5. HTML 报告生成（含图表）
6. SQLite 结果归档与历史对比

## 目录结构

```text
intra_vuln_assessor/
├── main.py
├── requirements.txt
├── README.md
└── vuln_assessor
    ├── cli.py
    ├── config.py
    ├── models.py
    ├── orchestrator.py
    ├── scanners
    ├── vuln
    ├── risk
    ├── report
    └── storage
```

## 快速开始

```bash
cd /home/yu/intra_vuln_assessor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py scan --target 192.168.1.0/24
```

执行完成后：

- HTML 报告输出到 `reports/`
- 扫描记录写入 `data/scans.db`

## 详细文档导航

1. 使用手册（从安装到演示）：`docs/usage_guide.md`
2. 核心代码讲解（按调用链路）：`docs/code_walkthrough.md`
3. 10分钟答辩讲稿：`docs/defense_script_10min.md`
4. 完整测试报告：`docs/test_report.md`
5. 第5章可粘贴稿：`docs/thesis_chapter5_paste_ready.md`
6. 毕设实施计划：`docs/implementation_steps.md`
7. 风险模型与规则管理：`docs/risk_rule_management_guide.md`

## 常用命令

### 1) 执行扫描

```bash
python3 main.py scan \
  --target 192.168.1.0/24 \
  --methods icmp,arp,syn \
  --ports 22,80,443,445,3306,3389 \
  --name round1
```

带资产画像的扫描（用于改进风险量化）：

```bash
python3 main.py scan \
  --target 192.168.1.0/24 \
  --methods icmp,arp,syn \
  --ports 22,80,443,445,3306,3389 \
  --asset-profile docs/asset_profile.example.json \
  --name round1_with_profile
```

### 2) 查看历史记录

```bash
python3 main.py history --limit 10
```

### 3) 对比两次扫描差异

```bash
python3 main.py compare --base 1 --new 2
```

### 4) 规则库管理

查看规则库统计：

```bash
python3 main.py rules list
```

手动导入规则（推荐用于论文主实验）：

```bash
python3 main.py rules import \
  --input docs/rules_feed.example.json \
  --mode merge
```

自动更新规则（从远程 JSON）：

```bash
python3 main.py rules update \
  --url https://example.com/my_rules.json \
  --mode merge
```

### 5) 启动 Web 前端

```bash
python3 main.py web --host 0.0.0.0 --port 5000 --max-concurrent 3
```

浏览器访问：`http://127.0.0.1:5000`

Web 前端功能：

1. 提交后台扫描任务（支持并发任务队列）；
2. 查看任务状态与历史扫描；
3. 查看扫描详情（资产、服务、漏洞）；
4. 对比两次扫描的服务识别差异与漏洞匹配差异（含风险分变化）。

## 本地复现实验（推荐）

为了便于你做毕业设计演示和论文截图，项目提供了可控实验靶场：

1. 模拟 `OpenSSH 7.4`（端口 `2222`）
2. 模拟 `Redis 6.2.5`（端口 `6379`）

一键运行：

```bash
./lab/run_demo_scan.sh demo_lab_scan_round1
```

分步运行：

```bash
./lab/start_demo_lab.sh
python3 main.py scan --target 127.0.0.1/32 --methods icmp --ports 2222,6379 --name demo_lab_manual
./lab/stop_demo_lab.sh
```

详细说明见：`docs/demo_lab_guide.md`

## 实现说明（与你任务书的一一对应）

1. 资产探测模块：`vuln_assessor/scanners/discovery.py`
2. 服务识别模块：`vuln_assessor/scanners/service_fingerprint.py`
3. 漏洞匹配模块：`vuln_assessor/vuln/matcher.py`
4. 风险评估模块：`vuln_assessor/risk/evaluator.py`
5. 报告生成模块：`vuln_assessor/report/generator.py`
6. 数据存储与历史对比：`vuln_assessor/storage/repository.py`
7. 系统编排流程：`vuln_assessor/orchestrator.py`
8. Web 前端与并发任务：`vuln_assessor/webapp.py`

## 风险模型（v2）

当前风险分计算为：

```text
Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence
```

其中：

1. `CVSS`：漏洞基础评分；
2. `AssetCriticality`：资产重要性（可由 `--asset-profile` 注入）；
3. `PortExposure`：端口暴露风险；
4. `ExploitMaturity`：漏洞可利用性（规则字段，可缺省）；
5. `MatchConfidence`：服务识别与版本匹配置信度（系统自动估计）。

资产画像示例：`docs/asset_profile.example.json`

## 自动导入 vs 手动导入（本科毕设建议）

推荐使用“混合方案”：

1. 论文主实验：手动精选规则（可控、可复现、易解释）；
2. 系统能力展示：自动更新命令（体现工程扩展性）。

详细说明见：`docs/risk_rule_management_guide.md`

## 并发扫描能力说明

当前系统支持两层并发：

1. 扫描引擎内部并发：主机与端口探测采用线程池并发执行；
2. Web 任务级并发：`main.py web --max-concurrent N` 可并发执行 N 个扫描任务。

说明：

1. SQLite 在高并发写入下吞吐有限，建议 `max-concurrent` 取 `2~4`；
2. 并发过高会增加 `nmap` 与网络资源占用，建议按实验环境逐步调参。

## 注意事项

- `arp` 扫描依赖 `scapy` 且通常需要 root 权限；未满足条件时会自动跳过 ARP 结果。
- 服务识别优先调用 `nmap`；若系统无 `nmap`，会退化到 socket 端口探测与基础服务推断。
- 自动更新接口要求远程地址返回 JSON 列表，字段结构与 `docs/rules_feed.example.json` 一致。
- 当前 `rules.json` 为可扩展示例规则库，建议你按论文测试环境补充更完整规则。
- `scan` 参数中的端口与扫描方法做了严格校验，非法输入会返回可读错误提示。
- `compare` 命令与 Web 对比页会校验扫描 ID 是否存在，避免误把不存在 ID 当作空基线。
