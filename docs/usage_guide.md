# 项目使用手册（一步步实操）

本手册面向“第一次接触该项目”的同学，目标是让你完整跑通：**扫描 -> 风险评估 -> 对比 -> Web演示**。

## 1. 环境准备

## 1.1 前置条件

1. 操作系统：Linux（推荐 Ubuntu）
2. Python：`3.10+`
3. 建议工具：`nmap`、`ping`
4. 可选依赖：`scapy`（用于 ARP 扫描，通常需要 root）

## 1.2 安装步骤

```bash
cd /home/yu/intra_vuln_assessor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

验证 CLI 是否正常：

```bash
python3 main.py --help
```

---

## 2. 第一次完整跑通（推荐）

## 2.1 方式A：一键演示（最快）

```bash
./lab/run_demo_scan.sh demo_lab_scan_round1
```

你会得到：

1. 一份 HTML 报告：`reports/demo_lab_scan_round1.html`
2. 一条历史记录：写入 `data/scans.db`

## 2.2 方式B：分步演示（适合论文截图）

启动靶场：

```bash
./lab/start_demo_lab.sh
```

执行扫描：

```bash
python3 main.py scan \
  --target 127.0.0.1/32 \
  --methods icmp \
  --ports 2222,6379 \
  --name demo_lab_manual
```

停止靶场：

```bash
./lab/stop_demo_lab.sh
```

---

## 3. 常用命令与建议用法

## 3.1 扫描命令

```bash
python3 main.py scan \
  --target 192.168.1.0/24 \
  --methods icmp,arp,syn \
  --ports 22,80,443,445,3306,3389 \
  --name round1
```

参数说明：

1. `--target`：目标网段，支持 CIDR
2. `--methods`：`icmp`/`arp`/`syn` 组合（按 `icmp -> arp -> syn` 顺序逐层补充）
3. `--ports`：端口列表或范围（如 `22,80` 或 `1-1024`）
4. `--name`：报告名（已做安全规范化）

注意：

1. 端口参数现在是严格校验，错误会直接提示；
2. 方法参数也会严格校验，避免误填后静默回退默认值。
3. `syn` 用于发现仅开放端口的主机（半开 SYN，需要 root 或 `CAP_NET_RAW` 且依赖 `scapy`）。
4. 端口探测由 `nmap -sV` 阶段完成，`--ports` 控制扫描端口范围。

## 3.2 历史记录

```bash
python3 main.py history --limit 10
```

## 3.3 扫描结果对比

```bash
python3 main.py compare --base 16 --new 17
```

输出包含：

1. 服务变化：新增/消失/持续
2. 漏洞变化：新增/修复/持续
3. 持续漏洞风险变化：风险分与等级变化

注意：对比命令现在会校验扫描 ID 是否存在。

## 3.4 规则管理

查看规则统计：

```bash
python3 main.py rules list
```

手动导入（论文主实验推荐）：

```bash
python3 main.py rules import --input docs/rules_feed.example.json --mode merge
```

自动更新（展示扩展能力）：

```bash
python3 main.py rules update --url https://example.com/my_rules.json --mode merge
```

---

## 4. Web 前端使用

启动前端：

```bash
python3 main.py web --host 127.0.0.1 --port 5000 --max-concurrent 3
```

浏览器访问：

`http://127.0.0.1:5000`

页面操作顺序：

1. 在仪表盘提交扫描任务
2. 观察任务队列状态（queued/running/finished/failed）
3. 点击扫描 ID 查看详情页（资产/服务/漏洞）
4. 进入“结果对比”页面，选择两次扫描做差异分析

---

## 5. 并发扫描如何使用

系统支持两层并发：

1. 引擎内部并发：主机与端口探测线程池并发
2. Web 任务并发：`--max-concurrent N`

建议参数：

1. 毕设演示环境优先用 `2~4`
2. 并发过高可能导致 SQLite 写入等待、`nmap` 资源争用

---

## 6. 常见问题排查

## 6.1 `扫描参数错误: 无效端口参数`

原因：`--ports` 含非法值（如 `abc`、`70000`）。
处理：改为 `1-65535` 范围内数字。

## 6.2 `结果对比失败: 基线扫描 ID 不存在`

原因：输入了不存在的扫描 ID。
处理：先执行 `python3 main.py history --limit 20` 查询有效 ID。

## 6.3 ARP 扫描无结果

原因：未安装 `scapy` 或未使用 root 权限。
处理：优先使用 `icmp`，或在具备权限时启用 `arp` 扫描补充存活信息。

## 6.4 服务识别信息较少

原因：系统未检测到 `nmap`，自动回退到 socket 探测。
处理：安装 `nmap` 后重试。

---

## 7. 毕设答辩建议流程

1. 先展示系统结构与风险模型公式
2. 用 demo lab 跑 2 次扫描，制造“前后变化”
3. 在对比页展示服务/漏洞/风险分变化
4. 说明规则管理支持手动与自动更新
5. 总结并发能力与限制（SQLite、网络资源）
