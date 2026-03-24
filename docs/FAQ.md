# FAQ（常见问题 / 零基础版）

> 面向第一次使用本项目的同学：这里把“最容易卡住”的点集中解释一遍。
> 关键词：**依赖 / 权限 / 报告 / 数据库 / 置信度 / Web 并发**。

---

## Q1：我运行后提示 `ModuleNotFoundError: No module named 'scapy'`，怎么办？
A：这通常是 **scapy 没装** 或 **虚拟环境（venv）没激活**。

1) 先确认终端提示符里有 `(.venv)`（代表已激活）。
2) 在项目根目录重新安装依赖：`pip install -r requirements.txt`。
3) 如果你用 `sudo` 跑扫描，建议用 venv 里的解释器：`sudo .venv/bin/python main.py ...`，避免 sudo 调到系统 Python。

## Q2：我明明 `pip install` 了，为什么还是找不到 scapy？
A：最常见原因是你在“另一个 Python 环境”里安装了依赖。

请按顺序自查：
- 你是否在 `intra_vuln_assessor/` 目录？
- 你是否执行过 `source .venv/bin/activate`？
- 你运行脚本时是否用的同一个解释器（不要混用 `python3 main.py ...` 和 `sudo python3 main.py ...`）？

## Q3：为什么 `syn` 方法需要 root 或 `CAP_NET_RAW`？
A：`syn` 属于 **原始报文/原始套接字** 级别的半开探测，一般需要更高权限。

本项目的行为是：
- 有权限：执行 SYN 探测，用来补齐“禁 ICMP/ARP 但端口开放”的主机。
- 无权限：会给出提示，并 **降级继续后续流程**（不会因为 syn 失败就整体退出）。

## Q4：我不想每次都 sudo，有没有别的办法？
A：Linux 下可给 venv 的 Python 加 `CAP_NET_RAW`（有安全风险，只建议在自控实验机）。

示例（在项目根目录）：
`sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python3)"`

注意：这主要影响 SYN；而 ARP 在当前实现里通常仍要求 root。

## Q5：为什么 ARP 扫描经常“没结果”甚至被跳过？
A：ARP 有两个关键限制：

1) **只在同一二层局域网有效**：跨网段/路由场景 ARP 不适用。
2) **权限与依赖**：ARP 依赖 `scapy`，且当前实现通常在非 root 时会直接跳过。

如果你的环境是 WSL2，也可能因为网络形态导致 ARP 在真实局域网内不稳定。

## Q6：ICMP（ping）被禁了，是不是主机就不在线？
A：不是。

很多内网会屏蔽 ICMP Echo，导致“在线但 ping 不通”。
因此本项目采用递进式复合发现：先 ICMP，再用 ARP（局域网），最后用 SYN（更激进，但需要权限）补齐。

## Q7：我没有装 nmap，会发生什么？
A：服务识别会从 `nmap -sV` **降级** 为 socket/常见端口映射，结果更“粗”。

典型表现：
- `version`（版本）字段可能是空的；
- 规则匹配的 **置信度更低**；
- 报告中更容易出现 **LOW**，并提示 **需要手动确认漏洞**。

建议：Ubuntu/WSL2 用 `sudo apt install -y nmap` 安装。

## Q8：为什么“version 为空”会让置信度变 LOW，还提示“需要手动确认漏洞”？
A：因为很多漏洞只影响特定版本区间。

当 **版本缺失** 且规则的 `version_rule` 不是通配（不是 `*`）时，本项目会：
- 强制 `confidence_tier = LOW`
- 标记 `manual_confirmation_needed = True`
- 在建议中提示：**需要手动确认漏洞**

这是一种“误报控制”：宁可保守，也不把不确定性包装成确定结论。

## Q9：报告里匹配到 CVE，就代表一定存在漏洞吗？
A：不一定。

匹配是基于“指纹/端口/服务/版本规则”的推断，尤其在版本缺失或指纹不完整时，必须把它当作“待确认线索”。
建议在授权范围内用人工方式确认：登录设备、查看真实版本、二次验证等。

## Q10：我生成了报告，但打开后图表不显示/提示 assets 找不到？
A：因为报告不是单个 HTML 文件，而是“HTML + assets 资源目录”。

正确的输出结构是：
- `reports/<name>/report.html`
- `reports/<name>/assets/`

如果你只拷走 `report.html`，浏览器会找不到 `assets/`，图表脚本加载失败。
解决：拷贝整个 `reports/<name>/` 目录（或打包整个目录再传）。

## Q11：我扫过了，但 `history` 看不到记录，是不是没入库？
A：不一定，更多是 **数据库路径相对路径** 的“目录错位”。

默认 DB 是相对路径：`data/scans.db`。
如果你不在 `intra_vuln_assessor/` 目录运行命令，程序可能在别的目录新建了一个 `data/scans.db`，你就会以为“丢了历史”。

建议二选一：
1) 永远先 `cd intra_vuln_assessor` 再运行。
2) 显式指定数据库：`python3 main.py history --db data/scans.db --limit 10`，扫描也同理可加 `--db`。

## Q12：`--db` 应该填什么？相对路径还是绝对路径？
A：都可以。

新手建议用 **绝对路径**，最不容易混淆；做论文/长期实验也建议固定 `--db /abs/path/to/scans.db`。

## Q13：我用 `compare` 对比时提示 scan id not found（找不到 ID）？
A：常见原因有三类：

1) 你填错了 `--base/--new` 的数字；
2) 你切换了数据库（或默认 DB 实际指向了另一个目录的 `data/scans.db`）；
3) 该 ID 对应记录不在当前 DB 里。

排查顺序：
- 先 `python3 main.py history --limit 10` 看当前 DB 里有哪些 ID。
- 必要时加 `--db ...` 指向你真正想用的数据库。

## Q14：为什么我指定了 `--methods icmp,arp,syn`，但结果里看起来“syn 没跑”？
A：有两种常见情况：

1) **权限/依赖不足**：syn 依赖 scapy 且需要 root/CAP_NET_RAW，无权限会提示并降级。
2) **递进策略**：SYN 通常只对前两种方式没发现的主机做补齐，不是对所有 IP 都无差别猛扫。

## Q15：Web 模式下我提交很多任务，为什么有的任务要排队？
A：Web 有并发上限（参数 `--max-concurrent`）。

例如：`python3 main.py web --max-concurrent 3` 表示同一时间最多跑 3 个扫描任务；更多任务会进入队列等待。
这是为了避免 CPU/IO/网络资源被瞬间打满，导致整体更慢或不稳定。

## Q16：Web 提交任务后跳转（302）是不是失败了？
A：不一定。

在测试中，“提交请求返回 302”是正常行为（通常是重定向到任务详情/列表页）。
是否成功要看任务最终状态以及是否生成对应报告文件。

## Q17：我能在 Windows 原生环境跑吗？
A：不推荐。

原始报文权限、依赖安装更容易踩坑。建议使用 WSL2 Ubuntu 22.04+ 或真实 Ubuntu 主机。若只是演示流程，可先用 `--methods icmp` 跑通。

## Q18：最小化“先跑通”的命令是什么？
A：目标是先验证链路没问题，再逐步打开更强的发现能力。

建议路线：
1) 先 `python3 main.py --help` 确认 CLI 正常；
2) 用 demo 脚本跑一次（如果仓库提供）：`./lab/run_demo_scan.sh <name>`；
3) 再在真实网段上从 `--methods icmp` 开始，确认没权限问题后再加 `arp/syn`。

---

> 记住一句话：**扫描是“环境 + 权限 + 依赖”共同决定的结果**。
> 遇到异常时优先把链路跑通（demo / localhost），再把权限与依赖补齐。
