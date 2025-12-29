# 5 分钟快速上手

> 从零开始，快速体验 VulnScanner 的核心功能

---

## 前置条件

在开始之前，请确保你的电脑已安装：

- **Python 3.10+**（检查：`python3 --version`）
- **Nmap**（检查：`nmap --version`）
- **Git**（检查：`git --version`）

如果没有安装，请先参考 [环境安装指南](../INSTALLATION.md)。

---

## 第一步：获取代码

```bash
# 克隆项目
git clone https://github.com/your-repo/vuln_scanner.git
cd vuln_scanner

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -e .
```

---

## 第二步：同步漏洞数据库

VulnScanner 使用 NVD（National Vulnerability Database，国家漏洞数据库）来匹配漏洞。首次使用需要同步数据：

```bash
python -m cli.main nvd sync
```

> 这会从 NVD 下载漏洞数据到本地缓存，可能需要几分钟。

---

## 第三步：执行你的第一次扫描

### 方式一：扫描本机

```bash
# 扫描本机（127.0.0.1）
sudo venv/bin/python -m cli.main scan 127.0.0.1
```

### 方式二：扫描局域网设备

```bash
# 扫描你的路由器（假设 IP 是 192.168.1.1）
sudo venv/bin/python -m cli.main scan 192.168.1.1
```

> **为什么需要 sudo？**
> 主机发现功能需要发送 ICMP/ARP 数据包，这需要 root 权限。

---

## 第四步：查看扫描结果

扫描完成后，你会看到类似这样的输出：

```
╭─────────────────── 扫描完成 ───────────────────╮
│  扫描 ID: 1                                    │
│  发现主机: 1                                   │
│  发现服务: 5                                   │
│  匹配漏洞: 12                                  │
│  扫描耗时: 45.2s                               │
╰────────────────────────────────────────────────╯

主机风险评估:
┌──────────────┬────────┬────────┬──────────────┐
│ IP           │ 评分   │ 等级   │ 漏洞数       │
├──────────────┼────────┼────────┼──────────────┤
│ 192.168.1.1  │ 35.2   │ HIGH   │ 12           │
└──────────────┴────────┴────────┴──────────────┘
```

---

## 第五步：生成报告

将扫描结果导出为 PDF 报告：

```bash
# 生成 PDF 报告（1 是扫描 ID）
python -m cli.main report 1 --format pdf -o my_first_report.pdf
```

用浏览器或 PDF 阅读器打开 `my_first_report.pdf`，你会看到一份专业的漏洞扫描报告。

---

## 第六步：启动 Web 界面（可选）

如果你更喜欢图形界面：

```bash
# 启动 Web 服务
sudo venv/bin/python -m web.app
```

然后打开浏览器访问：**http://localhost:5000**

你会看到一个漂亮的仪表盘界面，可以：
- 创建新的扫描任务
- 查看扫描历史
- 导出报告
- 查看网络拓扑图

---

## 常用命令速查

| 命令 | 功能 |
|------|------|
| `scan <目标>` | 执行扫描 |
| `scan <目标> --verify` | 扫描 + 主动验证（弱密码检测等） |
| `history` | 查看扫描历史 |
| `report <ID> --format pdf` | 生成 PDF 报告 |
| `compare <ID1> <ID2>` | 对比两次扫描结果 |
| `nvd status` | 查看漏洞库状态 |

---

## 遇到问题？

- 扫描没有结果？→ 确保目标主机在线，且没有被防火墙阻挡
- 权限错误？→ 使用 `sudo` 运行扫描命令
- NVD 同步失败？→ 检查网络连接，或使用离线数据包

更多问题请查看 [常见问题](../FAQ.md)。

---

## 下一步

- [多主机演示环境搭建](multi_host_demo.md) - 用 Docker 创建漏洞靶场
- [系统架构设计](../ARCHITECTURE.md) - 了解系统是如何工作的
- [核心模块详解](../modules/01_core.md) - 深入了解扫描流水线
