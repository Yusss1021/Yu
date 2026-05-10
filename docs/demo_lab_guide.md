# 本地靶场指南（Windows 主控机）

本指南用于在你的 Windows 主控机上快速复现实验环境，适合：

- GUI 冒烟
- 规则匹配验证
- 主动探测验证
- 论文截图
- 答辩演示

## 1. 靶场拓扑

当前默认靶场位于回环网段：

```text
127.0.0.0/29
```

默认服务包括：

- `127.0.0.1:8080` -> 模拟 `nginx`
- `127.0.0.2:2222` -> 模拟 `OpenSSH 7.4`
- `127.0.0.3:2121` -> 模拟 `FTP`
- `127.0.0.4:6379` -> 模拟 `Redis 6.2.5`

## 2. 一键运行

最简单的方式：

```text
lab\run_demo_scan.bat demo_lab_scan_round1
```

等价命令：

```powershell
python lab\lab_manager.py scan --name demo_lab_scan_round1
```

这个命令会：

1. 启动靶场
2. 执行一次扫描
3. 生成报告
4. 写入历史数据库

## 3. 分步运行

### 3.1 启动靶场

```text
lab\start_demo_lab.bat
```

或：

```powershell
python lab\lab_manager.py start
```

### 3.2 查看状态

```powershell
python lab\lab_manager.py status
```

### 3.3 用 GUI 演示

推荐输入：

- 目标网段：`127.0.0.0/29`
- 资产发现：优先用 `icmp`
- 分析页端口：`2121,2222,6379,8080`

推荐演示顺序：

1. `资产发现`
2. `漏洞匹配与服务识别`
3. `开启资产画像` 再做第二轮分析
4. `开启主动探测 / 弱口令尝试` 做第三轮分析
5. `报告对比`
6. `Web 报告中心`

### 3.4 用 CLI 演示

```powershell
python main.py scan `
  --target 127.0.0.0/29 `
  --methods icmp `
  --ports 2121,2222,6379,8080 `
  --name demo_lab_manual `
  --db data\scans.db
```

### 3.5 停止靶场

```text
lab\stop_demo_lab.bat
```

或：

```powershell
python lab\lab_manager.py stop
```

## 4. 预期结果

### 4.1 默认分析

通常应识别出 4 个服务，并命中：

- OpenSSH 相关规则
- Redis 相关规则
- FTP 相关规则
- HTTP 相关规则

### 4.2 开启主动探测

通常还会新增：

- `CFG-REDIS-UNAUTH-0001`
- `CFG-FTP-ANON-0001`

### 4.3 开启弱口令尝试

如果依赖齐全，通常还会新增：

- `CFG-FTP-WEAK-PASSWORD-0002`

## 5. 当前靶场的边界

这套靶场非常适合验证：

- GUI 主流程
- Web 报告中心
- 规则命中
- 主动探测
- 资产画像对评分的影响

但它不适合验证：

- ARP 的真实二层表现
- 公网连通性
- 真实交换网络中的广播与权限行为

所以如果你在这个靶场里发现：

- `ARP` 单独发现不到主机
- `SYN` 单独发现效果不明显

这并不代表程序异常。

## 6. 相关文件

- `lab/mock_http_nginx.py`
- `lab/mock_ssh.py`
- `lab/mock_ftp.py`
- `lab/mock_redis.py`
- `lab/lab_manager.py`
- `lab/start_demo_lab.bat`
- `lab/stop_demo_lab.bat`
- `lab/run_demo_scan.bat`
