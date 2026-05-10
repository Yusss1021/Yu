# 面向企业内部网络的脆弱性扫描与风险评估系统

本项目当前以 **Windows 桌面 GUI** 为主控入口，Web 端只承担 **报告中心** 职责。

当前主流程：

1. `资产发现` 页独立执行主机发现，生成资产发现报告
2. `漏洞匹配与服务识别` 页独立输入目标网段，使用 `nmap` 进行分析并生成分析报告
3. `规则库导入` 页默认做本地规则导入，远程 URL 更新保留在高级功能
4. `报告对比` 页默认只对比分析报告
5. `Web 报告中心` 页支持一键启动、打开、停止 Web

## 目录结构

```text
intra_vuln_assessor/
├── main.py                     # CLI/GUI 统一入口
├── install_deps.bat            # 一键安装依赖（首次使用先跑这个）
├── start_gui.bat               # Windows 桌面双击启动
├── requirements.txt            # 主路径最小依赖
├── requirements-advanced.txt   # scapy/paramiko/pymysql
├── README.md                   # 本文件
├── docs/                       # 用户文档与论文材料
├── lab/                        # 本地回环靶场
├── tests/                      # 单元测试
├── reports/                    # HTML 报告输出
├── data/                       # SQLite 数据库与快照
└── vuln_assessor/              # 核心模块
```

## Windows 快速开始

### 1. 一键安装依赖（推荐）

首次使用，在资源管理器中直接双击：

```text
install_deps.bat
```

该脚本自动完成：检测 Python → 创建虚拟环境 → 安装主依赖 → 检测 nmap → 可选安装高级依赖。

### 2. 手动安装（作为备选）

```powershell
cd C:\path\to\intra_vuln_assessor
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> **注意**：`start_gui.bat` 只负责启动 GUI，不安装依赖。跳过安装直接双击启动会因缺少依赖而失败。

当前 `requirements.txt` 包含：
- `jinja2` — HTML 报告模板渲染
- `flask` — Web 报告中心后端服务

### 2. 安装 `nmap`

第二页“漏洞匹配与服务识别”**硬依赖 `nmap`**。如果未安装或 `nmap.exe` 不在 `PATH` 中，该页会直接报错，不会生成伪分析结果。

安装完成后请确认：

```powershell
nmap -V
```

### 3. 如需更完整的 ARP / SYN 资产发现能力，再安装高级依赖

```powershell
python -m pip install -r requirements-advanced.txt
```

说明：

1. `requirements.txt` 是 Windows 主路径最小依赖
2. `requirements-advanced.txt` 放 `scapy` 这类高摩擦依赖
3. Windows 下 ARP / SYN 还可能受底层驱动或权限影响；能力不足时 GUI 会自动降级并记录原因

### 4. 启动桌面控制台

```powershell
python main.py gui
```

或者直接在资源管理器里双击：

```text
start_gui.bat
```

## GUI 页签说明

### 1. 资产发现

默认预设是 `递进式智能扫描（ICMP -> ARP -> SYN）`。

特点：

1. 只做资产发现，不会自动触发漏洞匹配
2. 会生成独立资产发现报告
3. 会保留资产发现历史与快照
4. Windows 下若 `ARP/SYN` 条件不足，会自动降级并继续

### 2. 漏洞匹配与服务识别

特点：

1. 直接输入目标网段，独立执行分析（不依赖资产发现快照）
2. 默认使用 `nmap` 标准扫描（`-sV -Pn --version-intensity 5`）
3. 支持快速 / 标准 / 深度扫描预设
4. `nmap` 不可用时会直接报错，不生成伪结果
5. 支持开启主动探测（Telnet/SNMP/Redis/FTP 匿名）和少量弱口令尝试（SSH/FTP/MySQL）
6. 所有结果通过统一风险模型（CVSS + 资产重要性 + 端口暴露面 + 利用成熟度 + 匹配置信度）量化评分

### 3. 规则库导入

1. 默认显示本地规则文件导入
2. 支持 `merge` / `replace`
3. 远程 URL 更新保留在高级功能折叠区

### 4. 报告对比

1. 默认只对比分析报告
2. 展示服务差异、漏洞差异和风险变化
3. 支持一键打开 Web 对比页

### 5. Web 报告中心

1. 一键启动本地 Web
2. 一键打开浏览器
3. 一键停止 Web
4. 默认展示分析报告历史，支持查看详情和删除报告
5. 资产发现报告请在"资产发现"页内查看和管理

## 本地靶场

项目现在提供 Windows 版本地靶场入口：

```text
lab\start_demo_lab.bat
lab\stop_demo_lab.bat
lab\run_demo_scan.bat
```

靶场默认使用回环多主机：

1. `127.0.0.2:2222` 模拟 OpenSSH
2. `127.0.0.1:8080` 模拟 nginx HTTP
3. `127.0.0.3:2121` 模拟 FTP
4. `127.0.0.4:6379` 模拟 Redis

## Web 端职责

Web 端现在只做：

1. 查看历史分析报告
2. 查看扫描详情
3. 做历史报告对比

Web 端不再负责：

1. 提交扫描任务
2. 调度后台扫描
3. 修改规则库

## 常用命令

```powershell
python main.py gui
python main.py history --limit 10
python main.py compare --base 1 --new 2
python main.py rules list
python main.py web --host 127.0.0.1 --port 5000
```

## 文档导航

1. 文档总入口：`docs/README.md`
2. 安装与环境检查：`docs/INSTALL.md`
3. GUI 与 CLI 使用步骤：`docs/usage_guide.md`
4. 零基础使用手册：`docs/USER_MANUAL.md`

## 补充说明

1. CLI `scan` 仍然保留，适合脚本化测试或论文实验复现
2. Linux / WSL2 仍可使用，但现在属于补充路线，不再是默认主路径
3. 旧版 Linux Web / Lab 启动脚本已移除，默认入口统一为 Windows 批处理文件
