# 常见问题解答 (FAQ)

---

## 安装问题

### Q1: 扫描时提示权限不足

**错误信息**:
```
PermissionError: [Errno 1] Operation not permitted
```

**原因**: ICMP/ARP/SYN 扫描需要原始套接字权限。

**解决方案**: 使用 sudo 运行：
```bash
sudo venv/bin/python -m cli.main scan 192.168.1.0/24
```

### Q2: Nmap 未找到

**错误信息**:
```
nmap: command not found
```

**解决方案**:
```bash
sudo apt install -y nmap
```

### Q3: Python 版本过低

**错误信息**:
```
SyntaxError: invalid syntax
```

**解决方案**:
```bash
# 安装 Python 3.10+
sudo apt install -y python3.10 python3.10-venv

# 使用新版本创建虚拟环境
python3.10 -m venv venv
source venv/bin/activate
pip install -e .
```

### Q4: pip 安装失败 (WeasyPrint)

**错误信息**:
```
ERROR: Could not build wheels for weasyprint
```

**解决方案**:
```bash
# 安装系统依赖
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev libcairo2

# 重新安装
pip install weasyprint
```

---

## 扫描问题

### Q5: 扫描结果为空

**可能原因**:
1. 目标网络不可达
2. 防火墙拦截 ICMP
3. 目标主机关闭

**解决方案**:
```bash
# 1. 先用 ping 测试连通性
ping -c 3 192.168.1.1

# 2. 尝试 ARP 扫描（局域网）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method arp

# 3. 尝试 SYN 扫描
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method syn

# 4. 使用全部方式
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --method all
```

### Q6: 扫描速度很慢

**可能原因**:
1. 目标范围太大
2. 端口范围太大
3. 网络延迟高

**解决方案**:
```bash
# 缩小扫描范围
sudo venv/bin/python -m cli.main scan 192.168.1.1-10

# 减少端口范围
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --ports 22,80,443

# 跳过服务识别
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --no-service
```

### Q7: 漏洞匹配结果为空

**可能原因**:
1. NVD 数据未同步
2. 服务版本信息不足
3. 没有已知漏洞

**解决方案**:
```bash
# 1. 同步 NVD 数据
python -m cli.main nvd sync

# 2. 检查 NVD 状态
python -m cli.main nvd status

# 3. 使用详细模式查看匹配过程
sudo venv/bin/python -m cli.main -v scan 192.168.1.1
```

---

## NVD 数据问题

### Q8: NVD API 请求过于频繁

**错误信息**:
```
HTTP 429: Too Many Requests
```

**解决方案**:
1. 申请免费 API Key：https://nvd.nist.gov/developers/request-an-api-key
2. 设置环境变量：
```bash
export NVD_API_KEY="your-api-key-here"
```

### Q9: NVD 同步失败

**可能原因**:
1. 网络连接问题
2. NVD 服务器暂时不可用

**解决方案**:
```bash
# 使用离线模式
python -m cli.main nvd sync --mode full --years 2024

# 强制重新下载
python -m cli.main nvd sync --mode full --force
```

### Q10: 数据库文件在哪里

**默认位置**: `data/scanner.db`

**自定义位置**:
```bash
export VULNSCAN_DB_PATH="/custom/path/scanner.db"
```

---

## Web 界面问题

### Q11: Web 界面无法访问

**检查步骤**:
```bash
# 1. 确认服务器已启动
sudo venv/bin/python -m web.app

# 2. 检查端口是否被占用
lsof -i :5000

# 3. 如需局域网访问
sudo venv/bin/python -c "from web.app import run_server; run_server(host='0.0.0.0')"
```

### Q12: 拓扑图不显示

**可能原因**:
1. 浏览器不支持 ECharts
2. 扫描结果无主机数据
3. JavaScript 错误

**解决方案**:
1. 使用现代浏览器（Chrome/Firefox/Edge）
2. 检查浏览器控制台（F12）是否有错误
3. 刷新页面或清除缓存

### Q13: 趋势图无数据

**原因**: 需要多次扫描才能生成趋势数据。

**解决方案**:
```bash
# 执行多次扫描
sudo venv/bin/python -m cli.main scan 192.168.1.0/24
# 等待完成后再次扫描
sudo venv/bin/python -m cli.main scan 192.168.1.0/24
```

### Q14: 扫描详情页图表为空（Risk Distribution 饼图灰色、Top Hosts 柱状图无数据）

**可能原因**:
1. 数据库权限问题：扫描使用 `sudo` 执行，数据库文件由 root 创建，Web 服务器无法读取
2. 扫描未发现主机或服务
3. 风险评分数据未生成

**解决方案**:

```bash
# 1. 检查数据库文件权限
ls -la data/scanner.db

# 2. 如果文件属于 root，修复权限
sudo chmod 666 data/scanner.db data/scanner.db-shm data/scanner.db-wal
# 或者
sudo chown $USER:$USER data/scanner.db data/scanner.db-shm data/scanner.db-wal

# 3. 验证数据库有数据
sqlite3 data/scanner.db "SELECT * FROM scan_results;"
sqlite3 data/scanner.db "SELECT * FROM hosts;"

# 4. 推荐：Web 服务也使用 sudo 运行
sudo venv/bin/python -m web.app
```

**根本原因说明**:

当使用 `sudo` 执行扫描时，数据库文件会以 root 用户创建。如果 Web 服务器以普通用户运行，则无法读取数据库，导致：
- 扫描列表显示记录但详情页数据为空
- 图表没有数据可渲染

**最佳实践**:

始终使用相同权限运行扫描和 Web 服务：
```bash
# 方式 1：都使用 sudo（推荐）
sudo venv/bin/python -m cli.main scan 192.168.1.0/24
sudo venv/bin/python -m web.app

# 方式 2：修复权限后普通用户运行 Web
sudo chmod 666 data/scanner.db*
python -m web.app
```

---

## 报告问题

### Q15: PDF 导出失败

**错误信息**:
```
OSError: cannot load library 'libpango-1.0.so'
```

**解决方案**:
```bash
# Ubuntu/Debian
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev libcairo2

# CentOS/RHEL
sudo yum install -y pango cairo
```

### Q16: 报告中文乱码

**解决方案**:
```bash
# 安装中文字体
sudo apt install -y fonts-noto-cjk
```

---

## 定时任务问题

### Q17: 定时任务不执行

**可能原因**:
1. 调度器未启动
2. 任务被禁用
3. Cron 表达式错误

**解决方案**:
```bash
# 1. 确认调度器运行
python -m cli.main schedule start

# 2. 检查任务状态
python -m cli.main schedule list

# 3. 验证 Cron 表达式格式
# 使用在线工具：https://crontab.guru/
```

### Q18: 调度器后台运行

```bash
# 使用 daemon 模式
sudo venv/bin/python -m cli.main schedule start --daemon

# 或使用 nohup
nohup sudo venv/bin/python -m cli.main schedule start > scheduler.log 2>&1 &
```

---

## 验证模块问题

### Q19: SSH 弱密码检测失败

**错误信息**:
```
paramiko not installed; skipping SSH checks
```

**解决方案**:
```bash
pip install paramiko
```

### Q20: MySQL 弱密码检测失败

**解决方案**:
```bash
pip install pymysql
```

### Q21: 验证结果未显示

**检查步骤**:
1. 确认使用了 `--verify` 参数
2. 确认目标有可验证的服务（SSH/MySQL/Redis/FTP/HTTPS）
3. 检查扫描详情页的"验证结果"标签

---

## 性能优化

### Q22: 大规模扫描优化

```bash
# 1. 分批扫描
sudo venv/bin/python -m cli.main scan 192.168.1.0/25
sudo venv/bin/python -m cli.main scan 192.168.1.128/25

# 2. 跳过不必要的步骤
sudo venv/bin/python -m cli.main scan 192.168.1.0/24 --no-vuln

# 3. 使用定时任务分散负载
python -m cli.main schedule add --name "Part1" --target 192.168.1.0/25 --cron "0 2 * * *"
python -m cli.main schedule add --name "Part2" --target 192.168.1.128/25 --cron "0 3 * * *"
```

### Q23: 数据库优化

```bash
# 清理旧数据
sqlite3 data/scanner.db "DELETE FROM scans WHERE started_at < date('now', '-30 days');"

# 压缩数据库
sqlite3 data/scanner.db "VACUUM;"
```

---

## 其他问题

### Q24: 如何备份数据

```bash
# 备份数据库
cp data/scanner.db data/scanner.db.backup

# 备份整个数据目录
tar -czvf backup.tar.gz data/
```

### Q25: 如何升级系统

```bash
# 拉取最新代码
git pull

# 更新依赖
pip install -e . --upgrade

# 数据库迁移（如有）
python -m cli.main db upgrade
```

### Q26: 如何卸载

```bash
# 删除虚拟环境
rm -rf venv

# 删除数据目录
rm -rf data

# 或完全删除项目
cd ..
rm -rf vuln_scanner
```

---

## 获取帮助

如果以上问题未能解决您的问题，请：

1. 查看详细日志：`python -m cli.main -v scan ...`
2. 检查系统日志：`journalctl -xe`
3. 联系作者获取支持

---

## 相关文档

- [安装指南](INSTALLATION.md)
- [快速上手](tutorials/quick_start.md)
- [系统架构](ARCHITECTURE.md)
- [CLI 接口](interfaces/cli.md)
- [Web API](interfaces/web_api.md)
