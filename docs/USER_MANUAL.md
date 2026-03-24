# 使用手册（零基础版）

> 读者画像：第一次接触“内网扫描/端口/漏洞匹配/报告”。
> 
> 开始前：请先按 `docs/INSTALL.md` 完成安装与自检（venv、依赖、可选 nmap、单元测试）。

## 1) 你将学会什么

- 5 分钟跑通 Demo Lab（本机模拟 SSH/Redis），生成报告并写入历史数据库
- CLI：`scan / history / compare / rules / web`
- Web：在 dashboard 提交任务、看 scan detail、做 compare、打开 report
- 理解输出文件（尤其是 report bundle）以及如何离线分享
- 理解置信度分档与“需要手动确认漏洞”

## 2) 快速开始（5分钟跑通 Demo Lab）

### 2.1 先进入目录 + 固定数据库（强烈推荐）

`data/scans.db` 是**相对路径**。为了避免“写到别的目录”，建议：先进入目录，再显式写死 `--db data/scans.db`。

```bash
cd intra_vuln_assessor
python3 main.py history --db data/scans.db --limit 1
```

### 2.2 一键跑通（推荐）

```bash
./lab/run_demo_scan.sh demo_lab_scan_round1
```

你会得到：

- 报告目录：`reports/demo_lab_scan_round1/`（打开 `reports/demo_lab_scan_round1/report.html`）
- 历史数据库：`data/scans.db`

如果你是 Linux 桌面环境：

```bash
xdg-open reports/demo_lab_scan_round1/report.html
```

## 3) CLI 使用（scan/history/compare/rules/web）

下面每个子命令都提供至少 1 段可复制粘贴的命令。

### 3.1 scan（执行一次扫描）

```bash
python3 main.py scan \
  --target 192.168.1.0/24 \
  --methods icmp,arp,syn \
  --ports 22,80,443,445,3306,3389 \
  --name round1 \
  --db data/scans.db
```

权限小结（只需记住结论）：

- `icmp` 通常普通用户可跑。
- `arp`/`syn` 常需要 **root 或 CAP_NET_RAW**；权限不足时程序会提示并降级继续。
- 使用 sudo 时，建议用 venv 的解释器，避免跑到系统 Python：

```bash
sudo .venv/bin/python main.py scan --target 192.168.1.0/24 --methods icmp,arp,syn --db data/scans.db
```

### 3.2 history（查看历史扫描记录）

```bash
python3 main.py history --db data/scans.db --limit 10
```

### 3.3 compare（对比两次扫描差异）

先用 `history` 找到有效扫描 ID。示例：base=16，new=17。

```bash
python3 main.py compare --db data/scans.db --base 16 --new 17
```

### 3.4 rules（规则库管理）

```bash
# 1) 查看规则库统计
python3 main.py rules list

# 2) 手动导入规则（离线可用，论文主实验推荐）
python3 main.py rules import \
  --input docs/rules_feed.example.json \
  --mode merge

# 3) 自动更新规则（可选：需要可访问的 URL）
python3 main.py rules update \
  --url https://example.com/my_rules.json \
  --mode merge
```

### 3.5 web（启动 Web 前端）

```bash
python3 main.py web --host 127.0.0.1 --port 5000 --max-concurrent 3 --db data/scans.db
```

浏览器访问：`http://127.0.0.1:5000`

### 3.6 单元测试命令（安装后自检）

在 `intra_vuln_assessor/` 目录执行：

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -t . -v
```

## 4) Web 使用（dashboard/scan detail/compare/report）

说明：Web 是本地演示控制台（不包含登录/账号/拓扑图等功能）。

### 4.1 dashboard（扫描控制台）

你可以：

1. 提交后台扫描任务（异步队列）
2. 查看任务状态：queued / running / finished / failed
3. 查看历史扫描列表（点击扫描 ID 进详情页）

页面会展示“注意事项”卡片：权限、准确性、合规（CLI 里扫描前也会打印同类提示）。

### 4.2 scan detail（扫描详情页）

会展示三类结果表：

- 资产发现（IP/MAC/发现方式/开放端口）
- 服务识别（主机/端口/协议/服务/产品版本）
- 漏洞匹配与风险评估（含置信度、手动确认提示）

### 4.3 compare（结果对比页）

选择两次扫描后，页面会展示：

- 服务识别差异：新增 / 消失 / 持续
- 漏洞差异：新增 / 修复 / 持续
- 持续漏洞风险变化：风险分与等级变化

### 4.4 report（报告查看）

在 dashboard 历史列表点“查看”，或在 scan detail 点“打开HTML报告”。

## 5) 输出文件与离线分享（重点解释 report bundle）

### 5.1 报告输出是目录包（关键事实）

报告输出不是“单个 HTML 文件”，而是一个目录包（report bundle）：

- `reports/<name>/report.html`
- `reports/<name>/assets/`

`assets/` 里是静态资源（例如图表脚本）。如果你只把 `report.html` 单独拷走，浏览器会找不到 `assets/`，图表可能不显示。

离线分享正确做法：复制整个 `reports/<name>/` 目录（或把该目录打包后再传）。

### 5.2 数据库（历史记录）

推荐固定数据库：`--db data/scans.db`，并建议先 `cd intra_vuln_assessor` 再运行命令。

## 6) 置信度与“需要手动确认漏洞”

### 6.1 置信度分档（阈值写死）

系统将 `match_confidence`（0~10）映射为三档：

- **HIGH**：`match_confidence >= 7.5`
- **MED**：`match_confidence >= 5.0`
- **LOW**：其他情况

### 6.2 版本缺失 + 非通配版本规则，会触发手动确认

当同时满足：

1) 服务版本缺失（常见：系统没装 nmap，或目标不暴露版本）
2) 规则的 `version_rule` 不是通配 `*`（需要做版本比较/区间判断）
系统会触发：LOW 置信度，并提示 **需要手动确认漏洞**。
这不是系统“确定有漏洞”，而是系统把不确定性显式告诉你：请通过人工方式核对真实版本（登录设备/查看软件版本/二次验证）。
## 7) 常见问题（至少 8 条，给排查步骤）
### 7.1 报告打开了但图表不显示（assets 找不到）
1. 你是否只复制了 `report.html`？（不行）
2. 必须保留目录结构：`reports/<name>/report.html` + `reports/<name>/assets/`。
3. 重新复制整个 `reports/<name>/` 再打开。
### 7.2 扫过了却看不到历史记录
1. 确认你在 `intra_vuln_assessor/` 目录运行。
2. 命令里固定带 `--db data/scans.db`。
3. 用 `python3 main.py history --db data/scans.db --limit 10` 验证。
### 7.3 扫描不到主机（不等于目标不在线）
1. 先跑 Demo Lab 排除“工具链路坏了”：`./lab/run_demo_scan.sh demo_lab_scan_round1`。
2. ICMP 可能被屏蔽：尝试加入 `syn`，并处理权限。
3. 确认 `--ports` 覆盖了你关心的端口，否则 SYN 阶段也可能发现不到。
### 7.4 ARP 没结果
1. ARP 只在同一二层局域网有效；跨网段/路由环境不适用。
2. ARP 通常需要 root；用 sudo 跑 scan。
3. 若缺依赖或权限不足会跳过，按 INSTALL.md 排查依赖。
### 7.5 SYN 没生效 / 提示权限不足
1. SYN 需要 root 或 `CAP_NET_RAW`，无权限会降级继续。
2. 用 `sudo .venv/bin/python ...`，确保是 venv 解释器。
3. 先用 `--methods icmp` 跑通，再逐步打开 `syn`。
### 7.6 服务版本经常为空、置信度偏低
1. 版本空通常意味着 nmap 没有生效（或目标不暴露版本）。
2. Ubuntu/WSL2 可安装：`sudo apt update && sudo apt install -y nmap`。
3. 版本缺失会触发更多“需要手动确认漏洞”，这是预期的误报控制机制。
### 7.7 为什么出现“需要手动确认漏洞”
1. 看该条是否 LOW 置信度。
2. 看版本字段是否为空。
3. 若“版本缺失 + 规则需要版本比较”，就必须人工确认真实版本。
### 7.8 `扫描参数错误: 无效端口参数`
1. `--ports` 只支持 `22,80,443` 或 `1-1024`，端口范围必须是 1~65535。
2. `--methods` 只支持 `icmp,arp,syn`。
3. 用最小命令定位：`python3 main.py scan --target 127.0.0.1/32 --methods icmp --ports 22 --db data/scans.db`。
### 7.9 `结果对比失败: 基线扫描 ID 不存在`
1. 先 `history` 找到真实 ID。
2. `compare` 时带同一个 `--db`。
3. base/new 任意一个填错都会报错，这是保护机制。
