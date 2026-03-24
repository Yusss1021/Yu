# 本地可复现实验指南（用于毕业设计演示）

本指南用于构造一个可控的实验环境，稳定产出漏洞匹配结果，适合做论文截图与演示视频。

## 1. 实验目标

在本机 `127.0.0.1` 启动两个模拟服务：

1. `OpenSSH 7.4`（端口 `2222`）
2. `Redis 6.2.5`（端口 `6379`）

然后执行一次扫描，预期命中 2 条漏洞规则。

## 2. 一键运行

在项目根目录执行：

```bash
./lab/run_demo_scan.sh demo_lab_scan_round1
```

预期输出包含：

- `识别服务: 2`
- `风险总数: 2`
- `报告路径: reports/demo_lab_scan_round1.html`

## 3. 分步运行（可用于答辩演示）

### 启动实验服务

```bash
./lab/start_demo_lab.sh
```

### 执行扫描

```bash
python3 main.py scan \
  --target 127.0.0.1/32 \
  --methods icmp \
  --ports 2222,6379 \
  --name demo_lab_manual
```

### 停止实验服务

```bash
./lab/stop_demo_lab.sh
```

## 4. 本次实测结果（2026-02-24）

使用命令：

```bash
./lab/run_demo_scan.sh demo_lab_scan_round5
```

扫描结果：

- 扫描 ID：`13`
- 识别服务：`2`
- 风险总数：`2`
- 报告文件：`reports/demo_lab_scan_round5.html`

匹配到的漏洞条目：

1. `2222/ssh` -> `CVE-2021-41617`
2. `6379/redis` -> `CVE-2021-32626`

## 5. 相关文件

- `lab/mock_ssh.py`：模拟 OpenSSH 服务
- `lab/mock_redis.py`：模拟 Redis 服务
- `lab/start_demo_lab.sh`：启动服务
- `lab/stop_demo_lab.sh`：停止服务
- `lab/run_demo_scan.sh`：启动并扫描的一键脚本
