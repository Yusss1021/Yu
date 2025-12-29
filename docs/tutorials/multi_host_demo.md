# 多主机演示环境搭建教程

> 使用 Docker 一键部署 7 台易受攻击的主机，体验完整的多主机扫描功能

---

## 什么是靶场环境？

**靶场（Vulnerable Lab）** 是专门设计的、包含已知漏洞的测试环境。我们使用 Docker 容器来模拟多台真实的服务器，让你可以安全地学习和测试漏洞扫描。

> **安全提示**：这些靶场只能在本地或隔离网络中使用，切勿暴露到公网！

---

## 环境架构

我们将部署 7 台易受攻击的主机：

| IP 地址 | 容器名 | 漏洞类型 | 暴露端口 |
|---------|--------|----------|----------|
| 172.28.0.2 | DVWA | SQL 注入、XSS、命令注入 | 8080 |
| 172.28.0.3 | WebGoat | OWASP Top 10 漏洞 | 8081 |
| 172.28.0.4 | Juice Shop | 现代 Web 应用漏洞 | 3000 |
| 172.28.0.5 | MySQL | 弱密码 (root/root123) | 3306 |
| 172.28.0.6 | Redis | 未授权访问 | 6379 |
| 172.28.0.7 | SSH | 弱密码 (root/root) | 2222 |
| 172.28.0.8 | FTP | 弱密码 (admin/admin123) | 21 |

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker 网络 (172.28.0.0/24)               │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │  DVWA   │ │ WebGoat │ │  Juice  │ │  MySQL  │           │
│  │ .0.2    │ │  .0.3   │ │  Shop   │ │  .0.5   │           │
│  └─────────┘ └─────────┘ │  .0.4   │ └─────────┘           │
│                          └─────────┘                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                       │
│  │  Redis  │ │   SSH   │ │   FTP   │                       │
│  │  .0.6   │ │  .0.7   │ │  .0.8   │                       │
│  └─────────┘ └─────────┘ └─────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 第一步：安装 Docker

### Ubuntu / Debian

```bash
# 更新包索引
sudo apt update

# 安装 Docker
sudo apt install -y docker.io docker-compose

# 启动 Docker 服务
sudo systemctl start docker
sudo systemctl enable docker

# 将当前用户加入 docker 组（需要重新登录生效）
sudo usermod -aG docker $USER
```

### Windows

1. 下载 [Docker Desktop](https://www.docker.com/products/docker-desktop)
2. 运行安装程序
3. 重启电脑
4. 启动 Docker Desktop

### macOS

```bash
# 使用 Homebrew 安装
brew install --cask docker

# 启动 Docker Desktop
open /Applications/Docker.app
```

### 验证安装

```bash
docker --version
# 输出类似：Docker version 24.0.0, build ...

docker-compose --version
# 输出类似：docker-compose version 1.29.2, build ...
```

---

## 第二步：启动靶场环境

进入项目目录，使用启动脚本：

```bash
cd vuln_scanner/demo

# 启动所有容器（首次会下载镜像，约 2-3GB）
./start_demo_env.sh start
```

你会看到类似输出：

```
=== VulnScanner 多主机演示环境 ===
正在启动 Docker 容器...
✓ vulnlab-dvwa       启动成功 (172.28.0.2)
✓ vulnlab-webgoat    启动成功 (172.28.0.3)
✓ vulnlab-juiceshop  启动成功 (172.28.0.4)
✓ vulnlab-mysql      启动成功 (172.28.0.5)
✓ vulnlab-redis      启动成功 (172.28.0.6)
✓ vulnlab-ssh        启动成功 (172.28.0.7)
✓ vulnlab-ftp        启动成功 (172.28.0.8)

演示环境就绪！
扫描目标：172.28.0.2-8
```

### 查看容器状态

```bash
./start_demo_env.sh status
```

---

## 第三步：初始化 DVWA

DVWA 需要初始化数据库才能使用：

1. 打开浏览器访问：**http://localhost:8080**
2. 使用默认账号登录：`admin` / `password`
3. 点击 **Create / Reset Database**
4. 重新登录

---

## 第四步：使用 CLI 扫描多主机

```bash
# 回到项目根目录
cd ..

# 扫描 7 台主机（约 3-5 分钟）
sudo venv/bin/python -m cli.main scan 172.28.0.2-8 --verify
```

### 命令参数说明

| 参数 | 含义 |
|------|------|
| `172.28.0.2-8` | 扫描 IP 范围 172.28.0.2 到 172.28.0.8 |
| `--verify` | 启用主动验证（弱密码检测等） |
| `-v` | 显示详细输出 |

### 预期结果

```
╭─────────────────── 扫描完成 ───────────────────╮
│  扫描 ID: 1                                    │
│  发现主机: 7                                   │
│  发现服务: 15                                  │
│  匹配漏洞: 50+                                 │
│  验证结果: 弱密码 4 个                         │
╰────────────────────────────────────────────────╯
```

---

## 第五步：使用 Web 界面扫描

### 启动 Web 服务

```bash
sudo venv/bin/python -m web.app
```

### 创建扫描任务

1. 打开浏览器访问：**http://localhost:5000**
2. 点击左侧菜单「新建扫描」
3. 填写扫描参数：
   - **目标**：`172.28.0.2-8`
   - **端口**：留空（使用默认）
   - **发现方式**：选择「All Methods」
   - **启用漏洞验证**：勾选
4. 点击「开始扫描」

### 查看扫描结果

扫描完成后，点击扫描记录进入详情页，你可以看到：

- **主机列表**：7 台主机的 IP、操作系统、风险评分
- **服务详情**：每台主机开放的端口和服务
- **漏洞列表**：匹配到的 CVE 漏洞
- **验证结果**：弱密码检测结果
- **修复建议**：针对每个漏洞的修复方案

---

## 第六步：查看网络拓扑

在扫描详情页，点击「查看拓扑」按钮，你会看到一个交互式网络拓扑图：

- **红色节点**：高危主机
- **橙色节点**：中危主机
- **绿色节点**：低危主机
- **连线**：同一子网的主机

你可以：
- 拖拽节点查看布局
- 点击节点查看详情
- 滚轮缩放视图

---

## 第七步：导出报告

### 通过 CLI

```bash
# 生成 PDF 报告
python -m cli.main report 1 --format pdf -o demo_report.pdf

# 生成 HTML 报告
python -m cli.main report 1 --format html -o demo_report.html

# 生成 JSON 数据
python -m cli.main report 1 --format json -o demo_report.json
```

### 通过 Web 界面

在扫描详情页，点击「导出报告」按钮，选择格式后下载。

---

## 第八步：清理环境

演示完成后，停止并删除容器：

```bash
cd demo

# 停止容器
./start_demo_env.sh stop

# 彻底删除（包括数据卷）
./start_demo_env.sh clean
```

---

## 常见问题

### Q: Docker 镜像下载太慢？

使用国内镜像加速：

```bash
# 编辑 Docker 配置
sudo vim /etc/docker/daemon.json

# 添加以下内容
{
  "registry-mirrors": ["https://mirror.ccs.tencentyun.com"]
}

# 重启 Docker
sudo systemctl restart docker
```

### Q: 端口被占用？

检查并停止占用端口的进程：

```bash
# 查看 8080 端口占用
sudo lsof -i :8080

# 停止占用的容器
docker stop <container_id>
```

### Q: 扫描没有发现主机？

1. 确认容器正在运行：`docker ps`
2. 确认网络连通：`ping 172.28.0.2`
3. 使用 `-v` 参数查看详细日志

---

## 下一步

- [核心模块详解](../modules/01_core.md) - 了解扫描的 6 个阶段
- [系统架构设计](../ARCHITECTURE.md) - 理解系统内部工作原理
- [风险评分模块](../modules/04_scoring.md) - 了解风险评分算法
