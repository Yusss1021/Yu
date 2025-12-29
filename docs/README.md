# VulnScanner 文档中心

> 网络漏洞扫描与风险评估系统 - 完整技术文档

---

## 快速导航

| 我想... | 查看文档 |
|---------|----------|
| 快速上手使用 | [快速上手教程](tutorials/quick_start.md) |
| 了解系统架构 | [系统架构](ARCHITECTURE.md) |
| 搭建演示环境 | [多主机演示](tutorials/multi_host_demo.md) |
| 查看 CLI 命令 | [CLI 接口文档](interfaces/cli.md) |
| 调用 REST API | [Web API 文档](interfaces/web_api.md) |
| 扩展开发 | [添加扫描器](development/extending_scanners.md) / [添加验证器](development/extending_verifiers.md) |

---

## 文档目录

### 入门指南

| 文档 | 说明 |
|------|------|
| [安装指南](INSTALLATION.md) | 环境要求、依赖安装、配置说明 |
| [快速上手](tutorials/quick_start.md) | 5 分钟入门教程 |
| [多主机演示](tutorials/multi_host_demo.md) | Docker 漏洞靶场搭建 |
| [常见问题](FAQ.md) | 故障排除和常见问题解答 |

### 系统设计

| 文档 | 说明 |
|------|------|
| [系统架构](ARCHITECTURE.md) | 整体架构、技术栈、数据流 |
| [术语表](GLOSSARY.md) | 专业术语解释 |

### 模块详解

| 文档 | 说明 |
|------|------|
| [01 核心模块](modules/01_core.md) | 数据模型、扫描流水线 |
| [02 扫描器模块](modules/02_scanners.md) | ICMP/ARP/SYN/Nmap 扫描器 |
| [03 NVD 漏洞库](modules/03_nvd.md) | API 客户端、缓存、匹配器 |
| [04 风险评分](modules/04_scoring.md) | 评分算法、权重计算 |
| [05 主动验证](modules/05_verifiers.md) | NSE/弱密码/SSL 检测 |
| [06 修复建议](modules/06_remediation.md) | 知识库、建议引擎 |
| [07 报告生成](modules/07_reporting.md) | HTML/PDF/JSON 报告 |
| [08 数据存储](modules/08_storage.md) | 数据库 Schema、Repository |

### 接口文档

| 文档 | 说明 |
|------|------|
| [CLI 命令行](interfaces/cli.md) | 所有命令及参数说明 |
| [Web API](interfaces/web_api.md) | REST API 端点和页面路由 |

### 开发指南

| 文档 | 说明 |
|------|------|
| [添加新扫描器](development/extending_scanners.md) | 扩展主机发现/服务识别 |
| [添加新验证器](development/extending_verifiers.md) | 扩展安全检测能力 |

---

## 文档结构

```
docs/
├── README.md                 # 本文件（文档索引）
├── INSTALLATION.md           # 安装指南
├── ARCHITECTURE.md           # 系统架构
├── GLOSSARY.md               # 术语表
├── FAQ.md                    # 常见问题
│
├── tutorials/                # 教程
│   ├── quick_start.md       # 快速上手
│   └── multi_host_demo.md   # 多主机演示
│
├── modules/                  # 模块详解
│   ├── 01_core.md           # 核心模块
│   ├── 02_scanners.md       # 扫描器
│   ├── 03_nvd.md            # NVD 集成
│   ├── 04_scoring.md        # 风险评分
│   ├── 05_verifiers.md      # 主动验证
│   ├── 06_remediation.md    # 修复建议
│   ├── 07_reporting.md      # 报告生成
│   └── 08_storage.md        # 数据存储
│
├── interfaces/               # 接口文档
│   ├── cli.md               # CLI 接口
│   └── web_api.md           # Web API
│
└── development/              # 开发指南
    ├── extending_scanners.md    # 扩展扫描器
    └── extending_verifiers.md   # 扩展验证器
```

---

## 阅读建议

### 新手用户

1. [安装指南](INSTALLATION.md) - 搭建环境
2. [快速上手](tutorials/quick_start.md) - 第一次扫描
3. [CLI 接口](interfaces/cli.md) - 了解更多命令

### 系统管理员

1. [多主机演示](tutorials/multi_host_demo.md) - 理解扫描场景
2. [Web API](interfaces/web_api.md) - 集成到现有系统
3. [常见问题](FAQ.md) - 解决运维问题

### 开发者

1. [系统架构](ARCHITECTURE.md) - 理解设计思路
2. [核心模块](modules/01_core.md) - 了解数据流
3. [添加扫描器](development/extending_scanners.md) - 扩展功能

### 答辩/汇报

1. [系统架构](ARCHITECTURE.md) - 技术选型说明
2. [风险评分](modules/04_scoring.md) - 算法设计亮点
3. [NVD 漏洞库](modules/03_nvd.md) - 数据来源说明

---

## 技术支持

遇到问题？

1. 查看 [常见问题](FAQ.md)
2. 检查 [安装指南](INSTALLATION.md) 的故障排除章节
3. 提交 Issue 到项目仓库
