# 安装指南（Windows 主路径）

本文只讲安装、自检和依赖边界。  
具体怎么操作 GUI，请看 [usage_guide.md](./usage_guide.md)。

## 1. 推荐环境

- Windows 10 / Windows 11
- Python 3.11+
- `nmap` 已正确安装并加入 `PATH`
- 推荐使用项目虚拟环境 `.venv`

说明：

- GUI 是当前主控入口
- Web 端只承担报告中心职责
- `ARP/SYN`、弱口令探测属于高级能力，不是主路径硬依赖

## 2. 一键安装（推荐）

首次使用，在资源管理器中直接双击：

```text
install_deps.bat
```

脚本会自动完成：Python 检测 → 虚拟环境创建 → 主依赖安装 → nmap 检测 → 高级依赖可选安装。

以下 3~5 节是手动安装步骤，供需要精细控制的用户参考。

---

## 3. 进入项目目录

```powershell
cd C:\path\to\intra_vuln_assessor
```

## 4. 创建虚拟环境

优先用：

```powershell
python -m venv .venv
```

如果你的机器装了 `py` 启动器，也可以用：

```powershell
py -3 -m venv .venv
```

激活：

```powershell
.venv\Scripts\activate
```

## 5. 安装主路径依赖

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

主路径依赖覆盖：

- GUI 与 Web 报告中心
- HTML 报告生成
- SQLite 历史记录
- 基础服务识别与规则匹配

## 6. 安装 `nmap`

第二页“漏洞匹配与服务识别”**硬依赖 `nmap`**，不可跳过。

### 6.1 Windows 安装

1. 从 https://nmap.org/download.html 下载 Windows 安装包
2. 安装时确保勾选 **"Register Path variable"**（或安装后将 `C:\Program Files (x86)\Nmap` 添加到系统 PATH）
3. 安装完成后**关闭并重新打开**终端，然后验证：

```powershell
nmap -V
```

### 6.2 验证失败的处理

如果 `nmap -V` 报"不是内部或外部命令"：

1. 确认 Nmap 安装目录（默认 `C:\Program Files (x86)\Nmap`）
2. 手动将安装目录加入系统环境变量 `PATH`
3. 重启终端后再次执行 `nmap -V`

如果 `nmap` 始终不可用，GUI 分析页会直接报错（这是设计行为，防止生成伪分析结果）。

## 7. 安装高级依赖

如果你需要以下能力，再安装：

```powershell
python -m pip install -r requirements-advanced.txt
```

高级依赖当前包括：

- `scapy`
  用于 ARP / SYN 相关能力
- `paramiko`
  用于 SSH 少量弱口令尝试
- `pymysql`
  用于 MySQL 少量弱口令尝试

说明：

- 即使不装高级依赖，GUI 主路径仍可运行
- 缺少高级依赖时，系统会在日志里提示并自动跳过对应能力

## 8. Windows 平台注意事项

### 8.1 ARP 与 SYN

在 Windows 下，ARP / SYN 是否可用，除了 Python 依赖，还受这些因素影响：

- `Npcap` / 驱动环境
- 是否为真实局域网
- 当前是否有代理、虚拟网卡、TUN/TAP 之类干扰
- 管理员权限

因此项目的实际策略是：

- 条件满足：执行 ARP / SYN
- 条件不足：自动降级继续，不让整个 GUI 失效

### 8.2 本地回环靶场

本项目自带靶场使用 `127.0.0.0/29` 回环网段。  
在这套靶场里：

- `ICMP` 适合作为主发现方式
- `ARP` 没有真实二层意义
- `SYN` 单独做资产发现也不具代表性

所以演示时不要把“回环靶场里 ARP/SYN 发现不到主机”误解成程序异常。

## 9. 自检命令

建议至少执行以下命令：

```powershell
python -V
nmap -V
python main.py --help
python -m unittest tests.test_desktop_gui_workflows tests.test_discovery_platform tests.test_workbench_flow -v
```

如果要做完整回归，可执行：

```powershell
python -m unittest tests.test_auth_probes tests.test_active_checks tests.test_confidence_tiers tests.test_config_parse_ports tests.test_desktop_gui_workflows tests.test_desktop_web_control tests.test_discovery_platform tests.test_gui_launcher tests.test_lab_manager tests.test_orchestrator_active_checks tests.test_workbench_flow -v
```

## 10. 启动方式

推荐直接双击：

```text
start_gui.bat
```

等价命令：

```powershell
python main.py gui
```

## 11. 常见问题

### 11.1 `nmap` 不可用

现象：

- GUI 分析页直接报错
- CLI `scan` 服务识别结果过少

处理：

1. 先执行 `nmap -V`
2. 确保安装目录已加入 `PATH`
3. 重开终端或重新打开 GUI

### 11.2 资产发现页提示自动降级

这不是 bug。它通常意味着：

- `scapy` 没装
- Npcap / 权限 / 网络形态不足
- 当前目标不适合 ARP/SYN

### 11.3 弱口令探测依赖缺失

如果日志里提示缺少 `paramiko` 或 `pymysql`：

- SSH/MySQL 对应弱口令探测会被跳过
- 规则匹配、Web、报告功能不受影响

### 11.4 GUI 双击没反应

优先检查：

1. 项目目录里是否存在可用 Python
2. `start_gui.bat` 是否能找到 `.venv`
3. 终端运行 `python main.py gui` 是否有明确报错
