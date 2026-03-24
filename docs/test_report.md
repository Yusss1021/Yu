# 项目验证报告（完整检查）

本报告记录了对项目的一次完整功能验证、异常场景验证、并发验证与真实环境可用性验证。

## 1. 报告信息

1. 验证时间：2026-02-24 16:08:52 +0800
2. 项目目录：`/home/yu/intra_vuln_assessor`
3. Python 版本：`3.10.12`
4. SQLite 版本：`3.37.2`
5. Nmap：`/usr/bin/nmap`（已安装）

---

## 2. 验证范围

本次覆盖：

1. CLI 全命令：`scan`/`history`/`compare`/`rules`/`web`
2. 参数与异常输入处理（端口、方法、网段、文件、URL）
3. Web 全链路（页面、提交任务、任务状态）
4. 并发场景（Web 任务并发、CLI 并发）
5. 真实环境可用性（本机真实服务端口扫描）

说明：`syn` 用于主机存活补充（半开探测，需 root 或 `CAP_NET_RAW`），端口与服务识别由 `nmap -sV` 阶段完成。

---

## 3. 发现并修复的问题

### 3.1 问题描述

当 `scan` 输入非法网段（如 `bad_cidr`）时，程序会抛 Python Traceback，用户体验差。

### 3.2 修复内容

在 `vuln_assessor/cli.py` 的 `handle_scan` 中，对 `orchestrator.run_scan(...)` 增加异常兜底：

1. 捕获异常；
2. 输出可读错误：`扫描执行失败: ...`；
3. 返回非零退出码。

修复位置：`vuln_assessor/cli.py:135`

### 3.3 回归结果

修复后命令：

```bash
python3 main.py scan --target bad_cidr --methods syn --ports 22
```

返回：

`扫描执行失败: 'bad_cidr' does not appear to be an IPv4 or IPv6 network`

且不再出现 Traceback。

---

## 4. 自动化命令级验证结果

本轮执行了 15 项命令测试，结果为：

`PASS=15 FAIL=0`

覆盖项包括：

1. help、合法扫描、带资产画像扫描；
2. 非法方法、非法端口、非法网段；
3. history、rules list/import/update；
4. compare 合法与非法 ID；
5. Web 提交任务 + 查询任务状态。

---

## 5. Web 与并发压力验证

## 5.1 Web 并发任务验证

测试方式：

1. 启动 `web --max-concurrent 3`
2. 连续提交 5 个扫描任务
3. 轮询任务状态直到结束

结果：

1. `task_count=5`
2. `final_ok=1`
3. 5 个提交请求全部 `302`
4. 报告目录 `reports/stress_task_*` 共 5 个（每个目录入口为 `reports/<name>/report.html`，同级 `assets/` 必须保留）

## 5.2 CLI 并发验证

同时启动 5 个 CLI 扫描任务（后台并发执行），结果全部通过：

1. `cli_stress_1=PASS`
2. `cli_stress_2=PASS`
3. `cli_stress_3=PASS`
4. `cli_stress_4=PASS`
5. `cli_stress_5=PASS`

---

## 6. 真实环境可用性验证

## 6.1 非靶场本机扫描

命令：

```bash
python3 main.py scan --target 127.0.0.1/32 --methods icmp,syn --ports 1-1024 --name real_env_localhost
```

结果：成功（扫描 ID=28，发现主机 1）。

## 6.2 本机真实服务扫描

验证流程：

1. 本机启动真实服务：`python3 -m http.server 18080`
2. 扫描端口：`--ports 18080`

结果：

1. 扫描成功（ID=29）
2. 识别服务数=1
3. compare 可识别新增服务：
   `127.0.0.1:18080/tcp http SimpleHTTPServer 0.6`

结论：系统在真实运行环境中可正常工作，不依赖 demo 靶场即可完成扫描与对比。

---

## 7. 回归验证摘要

关键命令均已再次执行并通过：

1. `python3 -m compileall main.py vuln_assessor docs`
2. `python3 main.py scan ...`（合法与非法输入）
3. `python3 main.py rules ...`（list/import/update）
4. `python3 main.py compare ...`（正常与异常）
5. `python3 main.py web ...` + `curl` 页面与任务接口

---

## 8. 当前结论与建议

## 8.1 当前结论

1. 当前代码可用，核心链路稳定；
2. 已修复本轮发现的实际 bug（非法网段 traceback）；
3. 未发现新的阻断性问题（P0/P1）。

## 8.2 建议

1. 后续增加 `pytest` 自动测试脚本，减少手工回归成本；
2. 若要更高并发，建议升级数据库（如 PostgreSQL）；
3. 论文附录可直接引用本报告作为“系统测试与验证”证据。

---

## 9. 新增功能回归验证（2026-02-27）

本节用于补充说明：项目在 2026-02-27 引入/完善了以下能力：

1. 报告输出升级为**离线报告包**（目录形式），可在无外网环境打开并显示图表；
2. 新增“置信度分级 + 手动确认提示”（低置信度显示“需要手动确认漏洞”）；
3. 新增“资产地图（分组视图）”统计章节；
4. 增加 `unittest` 自动化自检。

> 目录约定：以下命令建议在 `intra_vuln_assessor/` 目录内执行。DB 相对路径注意：建议所有命令都显式带 `--db data/scans.db`，避免相对路径导致的数据库分裂。

### 9.1 报告输出（离线报告包）验证

执行一次扫描（Demo Lab 更容易稳定复现）：

```bash
bash lab/start_demo_lab.sh
python3 main.py scan --target 127.0.0.1/32 --methods icmp --ports 2222,6379 --name offline_bundle_demo --db data/scans.db
bash lab/stop_demo_lab.sh
```

说明：报告输出为目录包，入口为 `reports/<name>/report.html`，同级 `assets/` 必须保留。

预期产物：
- 报告主页面：`reports/offline_bundle_demo/report.html`
- 同级资源目录：`reports/offline_bundle_demo/assets/`

> 离线分享注意：**拷贝整个 `reports/offline_bundle_demo/` 目录**，不要只拷贝 `report.html`。

### 9.2 离线报告“无外链”验证（必须）

检查 `report.html` 是否包含外链（http/https）：

```bash
python3 - <<'PY'
from pathlib import Path
p = Path('reports/offline_bundle_demo/report.html')
text = p.read_text(encoding='utf-8', errors='ignore')
print('has_http', ('http://' in text) or ('https://' in text))
print('uses_local_chart', 'assets/chart.umd.min.js' in text)
PY
```

预期：
- `has_http` 为 `False`
- `uses_local_chart` 为 `True`

### 9.3 SYN 权限降级验证（非 root / 无 CAP_NET_RAW）

在普通用户权限下执行：

```bash
python3 main.py scan --target 127.0.0.1/32 --methods icmp,syn --ports 2222,6379 --name syn_no_priv --db data/scans.db
```

预期：
- 扫描**不崩溃**，仍能生成报告与入库；
- 输出警告包含（两者之一即可）：
  - `need root/CAP_NET_RAW`（缺少权限）
  - `missing scapy`（scapy 未安装）
- 并提示：`will backfill open_ports from nmap/socket where possible`。

### 9.4 手动确认漏洞（版本缺失场景）验证

目标：验证当指纹版本缺失、且规则存在非通配 `version_rule` 时，会触发：
- `confidence_tier = LOW`
- 文案 **“需要手动确认漏洞”**
- 确认建议为 **“必须手动确认”**

推荐使用 Demo Lab：

```bash
bash lab/start_demo_lab.sh
python3 main.py scan --target 127.0.0.1/32 --methods icmp --ports 2222,6379 --name manual_confirm_demo --db data/scans.db
bash lab/stop_demo_lab.sh
```

预期：
- 打开 `reports/manual_confirm_demo/report.html`
- 在 Top 风险条目表与 Web scan detail 中能看到：
  - `置信度等级`（可能出现 LOW）
  - `确认建议`（LOW 对应“必须手动确认”）
  - 当需要人工确认时显示 **“需要手动确认漏洞”**

> 说明：若系统已安装并启用 `nmap`，可能获取到更完整版本信息，从而降低出现 LOW 的概率。

### 9.5 资产地图（分组视图）章节验证

执行一次扫描后（可复用 9.1 的 `offline_bundle_demo` 报告），检查离线报告是否包含章节标题：

```bash
python3 - <<'PY'
from pathlib import Path

p = Path('reports/offline_bundle_demo/report.html')
text = p.read_text(encoding='utf-8', errors='ignore')
print('has_asset_map_section', '资产地图（分组视图）' in text)
PY
```

预期：
- `has_asset_map_section` 为 `True`
- 报告中包含章节标题：**资产地图（分组视图）**
- 章节包含：
  - 子网分组统计表
  - 发现方式分布图
  - 开放端口 Top10 图
  - 置信度等级分布图

### 9.6 unittest 自动化自检

在仓库根目录运行：

```bash
python3 -m unittest discover -s intra_vuln_assessor/tests -p 'test_*.py' -t . -v
```

在项目目录运行：

```bash
cd intra_vuln_assessor
python3 -m unittest discover -s tests -p 'test_*.py' -t . -v
```

预期：所有测试通过。

### 9.7 Web 页面验证（注意事项与手动确认展示）

启动 Web：

```bash
python3 main.py web --host 127.0.0.1 --port 5000 --db data/scans.db --max-concurrent 1
```

预期：
- Dashboard 与 Compare 页面能看到“注意事项”；
- Scan detail 页面能看到 `置信度等级` / `确认建议`；当低置信度时出现 **“需要手动确认漏洞”**。
