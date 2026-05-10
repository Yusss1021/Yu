# Windows Entry, Lab, and Git Delivery Design

## Goal

把当前项目收口为适合 Windows 主控机直接交付的版本：

1. 提供可双击打开 GUI 的 Windows 入口
2. 删除 Linux 启动入口
3. 扩充本地规则库
4. 搭建一个基于 Windows 回环地址的“企业内网式”本地靶场
5. 清理明显冗余文件
6. 初始化 Git 并推送到用户提供的 `origin/master`

## Confirmed Constraints

- 主控机器现在是 Windows
- 双击入口只要求 `.cmd/.bat`，不要求本轮打包成 `.exe`
- Linux 启动入口可以删除
- 当前目录还不是 Git 仓库
- 远端仓库已明确：`https://github.com/Yusss1021/Yu.git`
- 当前本机已安装 `nmap`
- Windows 回环多地址可用，例如 `127.0.0.1`、`127.0.0.2`、`127.0.0.4`

## Delivery Scope

### 1. Windows Double-Click Entry

新增一个放在项目根目录的批处理入口，目标是：

- 双击后直接启动桌面 GUI
- 优先使用 `.venv\Scripts\pythonw.exe`
- 若没有 `.venv`，则回退到系统 `pyw` / `pythonw`
- 若仍不可用，再回退到普通 `python`
- 失败时给出可见错误提示，而不是静默无响应

### 2. Linux Entry Cleanup

删除当前已经不再符合主路径定位的 Linux 启动入口：

- `start_web.sh`
- `stop_web.sh`
- `web_control_panel.sh`

实验靶场里原有的 `.sh` 脚本也会删除，并由 Windows 版入口替代。

### 3. Local Rules Expansion

规则库将从当前的少量示例规则扩充到更适合毕设演示的规模，重点覆盖：

- OpenSSH
- Redis
- nginx / HTTP
- PostgreSQL
- MySQL
- Tomcat / Apache

扩充原则：

- 继续沿用本地静态 JSON 规则结构
- 优先补充与本地靶场可触发服务相关的规则
- 保持规则字段风格一致，避免引入新 schema

### 4. Windows Local Lab

靶场采用“Windows 回环多主机 + 多服务”方案：

- `127.0.0.2:2222` 模拟 OpenSSH
- `127.0.0.1:8080` 模拟 nginx HTTP
- `127.0.0.4:6379` 模拟 Redis

必要时可再补 1 个数据库型服务节点，但第一优先是确保现有识别链路稳定可复现。

靶场需要具备：

- 启动脚本
- 停止脚本
- 一键启动并执行验证扫描的脚本
- 运行状态与 PID 文件

### 5. Validation Standard

靶场验证至少覆盖：

- 资产发现能发现多个主机
- `nmap` 服务识别能识别出至少 SSH / HTTP / Redis 这几类服务
- 漏洞匹配能命中扩充后的本地规则
- 能生成报告并写入数据库
- 报告中心与 GUI 历史列表能正常打开这些结果

### 6. Cleanup Strategy

本轮只删除“明确已无主路径价值”的内容：

- Linux 启动入口
- Linux 靶场 `.sh` 入口
- 运行产物目录中的临时文件（如 `.runtime`、`lab/run`、`__pycache__`）

不删除：

- 论文草稿
- 测试文件
- 设计 / 计划文档

### 7. Git Strategy

Git 交付采用保守策略：

1. 在当前目录初始化 Git 仓库
2. 绑定 `origin`
3. 先探测远端 `master` 状态
4. 若远端为空，则直接首推
5. 若远端非空，则先拉取并判断是否存在无共同历史
6. 只有在确认不会粗暴覆盖远端内容的前提下才推送

## Risks

- Windows 下 `nmap` 对 mock 服务的识别结果可能与 Linux 有差异，因此靶场服务协议设计需要偏向标准响应
- 若远端仓库已有历史且和当前目录完全无共同历史，推送前可能需要一次显式合并策略判断
- 删除 Linux 入口后，旧文档中的相关引用必须同步修正

## Acceptance Criteria

- 用户可以在 Windows 上双击批处理文件直接打开 GUI
- 根目录不再保留 Linux Web 启动脚本
- 本地规则库规模和覆盖范围明显扩充
- 能在 Windows 本机跑起多主机回环靶场并完成一次成功扫描验证
- 当前工作目录完成 Git 初始化并成功推送到用户指定远端分支，若推送受阻则明确说明具体阻塞原因
