# CLI 命令行接口

> 完整的命令行使用指南

---

## 概述

VulnScanner 提供完整的命令行接口，基于 Click 框架实现。

```bash
# 入口
python -m cli.main [OPTIONS] COMMAND [ARGS]

# 或使用安装后的命令
vulnscan [OPTIONS] COMMAND [ARGS]
```

---

## 全局选项

```bash
vulnscan [OPTIONS] COMMAND

Options:
  -l, --lang TEXT     语言 (zh_CN/en_US)，默认 zh_CN
  -v, --verbose       启用详细输出
  --db PATH           指定数据库文件路径
  --help              显示帮助信息
```

**示例**：

```bash
# 使用英文界面
vulnscan --lang en_US scan 192.168.1.0/24

# 详细输出模式
vulnscan -v scan 192.168.1.0/24

# 使用自定义数据库
vulnscan --db /custom/path/scanner.db scan 192.168.1.0/24
```

---

## 命令列表

| 命令 | 功能 |
|------|------|
| `scan` | 执行漏洞扫描 |
| `history` | 查看扫描历史 |
| `report` | 生成扫描报告 |
| `compare` | 对比两次扫描 |
| `nvd` | 管理 NVD 漏洞库 |
| `schedule` | 管理定时任务 |
| `version` | 显示版本信息 |

---

## scan - 执行扫描

### 基本用法

```bash
vulnscan scan TARGET [OPTIONS]
```

### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `TARGET` | 必填 | - | 扫描目标（IP、CIDR、范围） |

### 选项说明

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--method` | `-m` | icmp | 主机发现方式 |
| `--ports` | `-p` | 1-1024 | 端口范围（SYN 扫描用） |
| `--verify` | - | False | 启用主动验证（弱密码检测等） |
| `--no-vuln` | - | False | 跳过漏洞匹配 |
| `--no-report` | - | False | 跳过报告生成 |
| `--output` | `-o` | 自动 | 报告输出路径 |

### 主机发现方式

| 值 | 说明 | 适用场景 |
|----|------|----------|
| `icmp` | ICMP Ping | 快速扫描，可能被防火墙阻挡 |
| `arp` | ARP 请求 | 局域网扫描，可获取 MAC |
| `syn` | TCP SYN | 隐蔽扫描，同时发现端口 |
| `all` | 全部方式 | 最全面，耗时长 |

### 使用示例

```bash
# 基础扫描（ICMP 发现）
sudo vulnscan scan 192.168.1.0/24

# 使用所有发现方式
sudo vulnscan scan 192.168.1.0/24 --method all

# 扫描指定端口范围
sudo vulnscan scan 192.168.1.0/24 --method syn --ports 1-65535

# 启用主动验证
sudo vulnscan scan 192.168.1.0/24 --verify

# 仅发现主机，不匹配漏洞
sudo vulnscan scan 192.168.1.0/24 --no-vuln

# 指定报告输出
sudo vulnscan scan 192.168.1.0/24 --output /path/to/report.html

# IP 范围扫描
sudo vulnscan scan 192.168.1.1-192.168.1.100

# 单个 IP 扫描
sudo vulnscan scan 192.168.1.1
```

### 输出示例

```
╭─────────────────── 扫描完成 ───────────────────╮
│  扫描 ID: 1                                    │
│  发现主机: 7                                   │
│  发现服务: 15                                  │
│  匹配漏洞: 50                                  │
│  验证结果: 弱密码 4 个                         │
╰────────────────────────────────────────────────╯

主机风险评估:
┌──────────────┬────────┬──────────┬──────────────┐
│ IP           │ 评分   │ 等级     │ 漏洞数       │
├──────────────┼────────┼──────────┼──────────────┤
│ 192.168.1.5  │ 85.2   │ CRITICAL │ 12           │
│ 192.168.1.3  │ 45.0   │ HIGH     │ 8            │
│ 192.168.1.1  │ 12.5   │ MEDIUM   │ 3            │
└──────────────┴────────┴──────────┴──────────────┘
```

---

## history - 查看历史

### 基本用法

```bash
vulnscan history [OPTIONS]
```

### 选项说明

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--limit` | `-n` | 10 | 显示记录数 |

### 使用示例

```bash
# 查看最近 10 条记录
vulnscan history

# 查看最近 20 条
vulnscan history --limit 20
```

### 输出示例

```
                    扫描历史
┌────┬──────────────────┬──────────────────┬───────────┐
│ ID │ Target           │ Started          │ Status    │
├────┼──────────────────┼──────────────────┼───────────┤
│ 3  │ 192.168.1.0/24   │ 2024-01-15 14:30 │ completed │
│ 2  │ 10.0.0.0/8       │ 2024-01-14 09:00 │ completed │
│ 1  │ 192.168.1.1      │ 2024-01-13 16:45 │ failed    │
└────┴──────────────────┴──────────────────┴───────────┘
```

---

## report - 生成报告

### 基本用法

```bash
vulnscan report SCAN_ID [OPTIONS]
```

### 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `SCAN_ID` | 整数 | 扫描任务 ID |

### 选项说明

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--format` | `-f` | html | 报告格式 (html/pdf/json) |
| `--output` | `-o` | 自动 | 输出文件路径 |

### 使用示例

```bash
# 生成 HTML 报告
vulnscan report 1 --output scan_report.html

# 生成 PDF 报告
vulnscan report 1 --format pdf --output scan_report.pdf

# 生成 JSON 数据
vulnscan report 1 --format json --output scan_data.json

# 使用英文报告
vulnscan --lang en_US report 1 --format pdf --output report_en.pdf
```

---

## compare - 扫描对比

### 基本用法

```bash
vulnscan compare SCAN_ID_OLD SCAN_ID_NEW
```

### 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `SCAN_ID_OLD` | 整数 | 旧扫描 ID |
| `SCAN_ID_NEW` | 整数 | 新扫描 ID |

### 使用示例

```bash
# 对比扫描 1 和扫描 2
vulnscan compare 1 2
```

### 输出示例

```
╭─────────────────── 扫描对比 ───────────────────╮
│  旧扫描: #1 (2024-01-13)                       │
│  新扫描: #2 (2024-01-14)                       │
╰────────────────────────────────────────────────╯

变化摘要:
  主机新增: 2
  主机移除: 1
  服务新增: 5
  服务移除: 3
  漏洞新增: 12
  漏洞修复: 8
  风险变化: +15.2

新增漏洞 (Top 5):
  - CVE-2024-1234 (CRITICAL) - 192.168.1.5
  - CVE-2024-5678 (HIGH) - 192.168.1.3
  ...

已修复漏洞 (Top 5):
  - CVE-2023-9999 (HIGH) - 192.168.1.2
  ...
```

---

## nvd - 漏洞库管理

### 子命令

| 子命令 | 说明 |
|--------|------|
| `nvd status` | 查看漏洞库状态 |
| `nvd sync` | 同步漏洞数据 |
| `nvd clear` | 清空本地缓存 |

### nvd status

```bash
vulnscan nvd status
```

输出：
```
NVD 漏洞库状态:
  初始化: 是
  CVE 总数: 245,678
  最后全量同步: 2024-01-10 03:00
  最后增量同步: 2024-01-15 08:00
  已导入年份: 2020, 2021, 2022, 2023, 2024
```

### nvd sync

```bash
vulnscan nvd sync [OPTIONS]
```

**选项**：

| 选项 | 短选项 | 默认值 | 说明 |
|------|--------|--------|------|
| `--mode` | `-m` | auto | 同步模式 (auto/full/incremental) |
| `--years` | `-y` | 2020-当前 | 年份范围（full 模式） |
| `--force` | `-f` | False | 强制重新下载 |

**同步模式**：

| 模式 | 说明 |
|------|------|
| `auto` | 未初始化时全量同步，否则增量同步 |
| `full` | 下载离线数据包（推荐首次使用） |
| `incremental` | 通过 API 获取最近更新（需要 API Key） |

**使用示例**：

```bash
# 自动模式（推荐）
vulnscan nvd sync

# 全量同步指定年份
vulnscan nvd sync --mode full --years 2020-2024

# 强制重新下载
vulnscan nvd sync --mode full --force

# 增量同步
vulnscan nvd sync --mode incremental
```

### nvd clear

```bash
vulnscan nvd clear
```

清空本地 NVD 缓存（需要重新同步）。

---

## schedule - 定时任务

### 子命令

| 子命令 | 说明 |
|--------|------|
| `schedule list` | 查看定时任务 |
| `schedule add` | 添加定时任务 |
| `schedule remove` | 删除定时任务 |
| `schedule enable` | 启用任务 |
| `schedule disable` | 禁用任务 |

### schedule add

```bash
vulnscan schedule add [OPTIONS]
```

**选项**：

| 选项 | 说明 |
|------|------|
| `--name` | 任务名称（必填） |
| `--target` | 扫描目标（必填） |
| `--cron` | Cron 表达式（必填） |
| `--method` | 发现方式 (icmp/arp/syn/all) |
| `--ports` | 端口范围 |

**Cron 表达式格式**：

```
分 时 日 月 周
*  *  *  *  *

示例：
0 2 * * *     每天凌晨 2:00
0 3 * * 0     每周日凌晨 3:00
0 9 * * 1     每周一上午 9:00
0 0 1 * *     每月 1 日零点
```

**使用示例**：

```bash
# 每天凌晨 2 点扫描内网
sudo vulnscan schedule add \
    --name "每日扫描" \
    --target 192.168.1.0/24 \
    --cron "0 2 * * *"

# 每周日深度扫描
sudo vulnscan schedule add \
    --name "周日深度扫描" \
    --target 192.168.1.0/24 \
    --cron "0 3 * * 0" \
    --method all
```

### schedule list

```bash
vulnscan schedule list
```

输出：
```
定时任务列表:
┌────┬──────────────┬──────────────────┬─────────────┬────────┐
│ ID │ 名称         │ 目标             │ Cron        │ 状态   │
├────┼──────────────┼──────────────────┼─────────────┼────────┤
│ 1  │ 每日扫描     │ 192.168.1.0/24   │ 0 2 * * *   │ 启用   │
│ 2  │ 周日深度扫描 │ 192.168.1.0/24   │ 0 3 * * 0   │ 启用   │
└────┴──────────────┴──────────────────┴─────────────┴────────┘
```

### schedule remove / enable / disable

```bash
vulnscan schedule remove 1     # 删除任务 1
vulnscan schedule disable 2    # 禁用任务 2
vulnscan schedule enable 2     # 启用任务 2
```

---

## version - 版本信息

```bash
vulnscan version
```

输出：
```
VulnScanner v1.0.0
Network Vulnerability Scanner & Risk Assessment System
Nmap: 7.94
```

---

## 常用命令组合

### 首次完整扫描

```bash
# 1. 同步漏洞库
vulnscan nvd sync

# 2. 执行完整扫描
sudo vulnscan scan 192.168.1.0/24 --method all --verify

# 3. 生成 PDF 报告
vulnscan report 1 --format pdf --output full_scan.pdf
```

### 日常监控

```bash
# 1. 快速扫描
sudo vulnscan scan 192.168.1.0/24

# 2. 与上次对比
vulnscan compare 1 2

# 3. 查看历史趋势
vulnscan history --limit 20
```

### 自动化扫描

```bash
# 添加定时任务
sudo vulnscan schedule add \
    --name "Daily Scan" \
    --target 192.168.1.0/24 \
    --cron "0 2 * * *"

# 查看任务列表
vulnscan schedule list
```

---

## 代码位置

| 功能 | 文件 | 行号 |
|------|------|------|
| CLI 入口 | `cli/main.py` | 84-100 |
| scan 命令 | `cli/main.py` | 103-270 |
| history 命令 | `cli/main.py` | 278-318 |
| report 命令 | `cli/main.py` | 321-410 |
| compare 命令 | `cli/main.py` | 430-500 |
| nvd 子命令 | `cli/main.py` | 550-650 |

---

## 下一步

- [Web API 接口](web_api.md) - 了解 REST API
- [快速上手教程](../tutorials/quick_start.md) - 实践操作指南
