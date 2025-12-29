# 安装指南

## 环境要求

### 操作系统
- Linux（推荐 Ubuntu 20.04/22.04/24.04）
- 需要 root 权限执行网络扫描

### 软件依赖
- Python 3.10 或更高版本
- Nmap 7.80 或更高版本
- SQLite3（Python 内置）

### 硬件要求
- CPU：双核及以上
- 内存：2GB 及以上
- 磁盘：500MB 可用空间

---

## 安装步骤

### 第一步：安装系统依赖

```bash
# 更新软件包列表
sudo apt update

# 安装 Python 和 pip
sudo apt install -y python3 python3-pip python3-venv

# 安装 Nmap（服务识别必需）
sudo apt install -y nmap

# 安装网络工具（可选，用于调试）
sudo apt install -y net-tools iputils-ping

# 安装 PDF 导出依赖（可选）
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2
```

### 第二步：进入项目目录

```bash
cd /path/to/vuln_scanner
```

### 第三步：创建虚拟环境

```bash
# 创建虚拟环境
python3 -m venv venv

# 激活虚拟环境
source venv/bin/activate

# 确认 Python 版本
python --version  # 应显示 Python 3.10+
```

### 第四步：安装项目依赖

```bash
# 安装项目（开发模式）
pip install -e .

# 或者仅安装依赖
pip install -r requirements.txt

# 安装可选验证模块依赖
pip install -e .[verify]
# 或
pip install paramiko pymysql
```

### 第五步：验证安装

```bash
# 检查 CLI 是否可用
python -m cli.main --help

# 检查 Nmap 是否安装
nmap --version

# 检查版本信息
python -m cli.main version
```

---

## 可选配置

### 配置 NVD API Key

NVD API 有请求频率限制，申请 API Key 可提高速率：

1. 访问 https://nvd.nist.gov/developers/request-an-api-key
2. 填写邮箱，提交申请
3. 邮件收到 Key 后设置环境变量：

```bash
export NVD_API_KEY="your-api-key-here"
```

**速率限制对比**：
| 配置 | 请求速率 |
|------|----------|
| 无 API Key | 0.6 次/秒 |
| 有 API Key | 5 次/秒 |

### 自定义数据库路径

默认数据库位置：`data/scanner.db`

可通过环境变量自定义：
```bash
export VULNSCAN_DB_PATH="/custom/path/scanner.db"
```

### 初始化 NVD 数据

首次使用前建议同步 NVD 数据：

```bash
# 自动同步（推荐）
python -m cli.main nvd sync

# 或指定年份
python -m cli.main nvd sync --mode full --years 2020-2024
```

---

## 快速验证

安装完成后，执行以下命令验证系统是否正常：

```bash
# 1. 检查 CLI
python -m cli.main version

# 2. 检查 NVD 状态
python -m cli.main nvd status

# 3. 扫描本机测试
sudo venv/bin/python -m cli.main scan 127.0.0.1

# 4. 启动 Web 界面
sudo venv/bin/python -m web.app
# 访问 http://localhost:5000
```

---

## 故障排除

### 问题：权限不足

```
PermissionError: [Errno 1] Operation not permitted
```

**解决**：使用 sudo 运行扫描命令：
```bash
sudo venv/bin/python -m cli.main scan <target>
```

### 问题：Nmap 未找到

```
nmap: command not found
```

**解决**：
```bash
sudo apt install -y nmap
```

### 问题：Python 版本过低

```
Python 3.9 or lower detected
```

**解决**：
```bash
sudo apt install -y python3.10 python3.10-venv
python3.10 -m venv venv
```

### 问题：pip 安装失败

```
ERROR: Could not build wheels for weasyprint
```

**解决**：安装系统依赖：
```bash
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2
```

---

## 下一步

- [快速上手](tutorials/quick_start.md) - 5 分钟入门教程
- [系统架构](ARCHITECTURE.md) - 了解整体设计
- [CLI 接口](interfaces/cli.md) - 命令行使用指南
- [Web API](interfaces/web_api.md) - REST API 文档
- [开发指南](development/extending_scanners.md) - 扩展开发
