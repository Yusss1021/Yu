# 安装指南（Ubuntu 22.04+ / WSL2 优先）

本文只讲安装与自检命令。如何跑一次完整扫描、怎么看报告与历史，请看 `docs/usage_guide.md`。

## 支持环境

- Ubuntu 22.04+（首选）
- WSL2 Ubuntu 22.04+（首选）
- macOS（可用，但 ARP/SYN 权限处理不同，建议只做演示或用 sudo）
- Windows（建议用 WSL2。原生 Windows 环境下原始报文权限和依赖更容易踩坑）

说明：ARP 属于二层探测，WSL2 的网络形态可能导致 ARP 在真实局域网内效果不稳定。需要 ARP 结果时，优先在真实 Ubuntu 主机上运行。

## 0) 进入项目目录

下面所有命令都假设你先进入项目根目录再执行：

```bash
cd intra_vuln_assessor
```

## 1) 检查 Python 是否可用

```bash
python3 --version
```

如果这里提示找不到 `python3`，先把 Python 3 安装好再继续。

## 2) 创建虚拟环境（.venv）并激活

建议从零创建一个干净的 venv，避免系统 Python 依赖混在一起。仓库里就算已经有 `.venv/`，也可以按下面步骤重建。

```bash
python3 -m venv .venv
source .venv/bin/activate
```

激活成功后，你的 shell 提示符里一般会出现 `(.venv)`。

## 3) 安装 Python 依赖

在虚拟环境已激活的前提下执行：

```bash
pip install -r requirements.txt
```

## 4) 安装系统 nmap（可选，但强烈推荐）

系统会优先使用 `nmap -sV` 做服务识别与版本指纹。没有 nmap 时会降级，结果会更粗。

Ubuntu / WSL2：

```bash
sudo apt update && sudo apt install -y nmap
```

macOS 备注：通常用 Homebrew 安装 nmap。

## 5) 权限说明（ARP / SYN 为什么需要更高权限）

- `icmp`：走系统 `ping`，一般普通用户就能跑。
- `arp`：依赖 `scapy`，并且当前实现会在非 root 时直接跳过 ARP。
- `syn`：依赖 `scapy`，需要 root 或 `CAP_NET_RAW`。无权限时会提示并降级继续。

你有两种常见做法：

### 方案 A：用 sudo 运行（最省事）

为了确保依赖来自你的 venv，不要用 `sudo python3 ...` 直接跑系统 Python。更稳的写法是用 venv 里的解释器：

```bash
sudo .venv/bin/python main.py scan --target 192.168.1.0/24 --methods icmp,arp,syn
```

如果你只想无权限跑通流程，可以先用 `--methods icmp`。

### 方案 B：给 Python 加 CAP_NET_RAW（有风险，谨慎）

这能让普通用户执行需要原始套接字的操作（主要影响 SYN）。它会降低系统安全边界，只建议在自己可控的实验机上使用。

在项目根目录执行：

```bash
sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python3)"
```

注意：

- 该方式只适用于 Linux。macOS 不走 setcap。
- 当前 ARP 逻辑仍要求 root，所以想要 ARP 结果，还是需要方案 A。
- Python 升级或替换后，cap 可能会失效，需要重新设置。

## 6) 自检命令（确认安装没问题）

在 `intra_vuln_assessor/` 目录内，并且已激活 `.venv` 后执行：

```bash
python3 main.py --help
python3 -m compileall .
python3 -m unittest discover -s tests -p 'test_*.py' -t . -v
```

## 7) 常见问题排查

### 7.1 scapy 导入失败（ImportError / ModuleNotFoundError）

常见现象：

- `ModuleNotFoundError: No module named 'scapy'`
- 或者扫描时提示缺少 scapy，ARP/SYN 被跳过

处理方式：

1. 确认你已经激活 venv（终端里有 `(.venv)`）。
2. 在项目根目录重新安装依赖：

   ```bash
   pip install -r requirements.txt
   ```

3. 如果你用 sudo 跑扫描，确保用的是 venv 的解释器：

   ```bash
   sudo .venv/bin/python main.py --help
   ```

### 7.2 系统缺少 nmap

常见现象：

- 命令行提示找不到 `nmap`
- 服务识别与版本字段偏空，漏洞匹配置信度变低

处理方式（Ubuntu / WSL2）：

```bash
sudo apt update && sudo apt install -y nmap
```

### 7.3 报告打开后提示 assets 找不到，图表不显示

当前报告输出是一个文件夹包，而不是单个 HTML 文件：

- `reports/<name>/report.html`
- `reports/<name>/assets/`（静态资源，比如图表脚本）

如果你只把 `report.html` 单独拷走，浏览器就会找不到 `assets/`。解决办法是拷贝整个 `reports/<name>/` 目录，或把该目录打包后再传。

### 7.4 数据库路径混乱（扫过了却看不到历史记录）

默认数据库路径是相对路径：`data/scans.db`。你如果不在 `intra_vuln_assessor/` 目录里执行命令，程序可能在别的目录新建了一个 `data/scans.db`。

推荐做法：

1. 永远先 `cd intra_vuln_assessor` 再运行。
2. 或者显式指定数据库位置：

   ```bash
   python3 main.py history --db data/scans.db --limit 10
   python3 main.py scan --db data/scans.db --target 192.168.1.0/24
   ```
