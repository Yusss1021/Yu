# Web API 接口

> REST API 和 Web 页面路由详解

---

## 概述

VulnScanner 提供基于 Flask 的 Web 界面和 REST API：

```
web/
├── __init__.py
├── app.py                 # Flask 应用工厂
├── views.py               # 页面路由（HTML 渲染）
├── api.py                 # REST API（JSON 响应）
└── templates/             # Jinja2 模板
```

**技术选型**：
- Flask 框架
- Flask-WTF（CSRF 保护）
- Jinja2 模板引擎
- ECharts（前端图表）

---

## 1. 应用启动

### 1.1 命令行启动

```bash
# 启动 Web 服务器
python -m web.app

# 或指定参数
python -c "from web.app import run_server; run_server(host='0.0.0.0', port=8080, debug=True)"
```

### 1.2 应用工厂

```python
# web/app.py:20-46

def create_app(config: Config = None) -> Flask:
    """创建并配置 Flask 应用"""
    app = Flask(__name__)

    # 配置
    app.config["SECRET_KEY"] = "..."
    app.config["DATABASE_PATH"] = str(config.database.path)
    app.config["LANGUAGE"] = config.language

    # CSRF 保护
    csrf.init_app(app)

    # 注册蓝图
    app.register_blueprint(views_bp)           # 页面路由
    app.register_blueprint(api_bp, url_prefix="/api")  # API 路由

    return app
```

---

## 2. 页面路由 (views.py)

### 2.1 路由总览

| URL | 方法 | 页面 | 功能 |
|-----|------|------|------|
| `/` | GET | dashboard | 仪表盘（扫描概览） |
| `/new_scan` | GET/POST | new_scan | 创建新扫描 |
| `/scans/<id>` | GET | scan_detail | 扫描详情 |
| `/scans/<id>/topology` | GET | topology | 网络拓扑图 |
| `/history` | GET | history | 扫描历史 |
| `/compare/<old>/<new>` | GET | compare | 扫描对比 |
| `/schedules` | GET | schedules | 定时任务管理 |

### 2.2 仪表盘 (Dashboard)

```python
# web/views.py:115-156

@views_bp.route("/")
def dashboard():
    """仪表盘 - 扫描概览"""
    # 获取最近扫描
    scans = scan_repo.get_all(limit=10)

    # 统计数据
    stats = {
        "total_scans": total_scans,
        "total_hosts": total_hosts,
        "total_vulns": total_vulns,
        "critical_hosts": critical_hosts,
    }

    return render_template("dashboard.html", scans=scans, stats=stats)
```

**页面内容**：
- 最近扫描列表
- 统计卡片（扫描数、主机数、漏洞数、高危主机）
- 安全趋势图（通过 API 异步加载）

### 2.3 新建扫描 (New Scan)

```python
# web/views.py:159-197

@views_bp.route("/new_scan", methods=["GET", "POST"])
def new_scan():
    """新建扫描页面"""
    if request.method == "POST":
        target = request.form.get("target")
        method = request.form.get("method", "icmp")
        ports = request.form.get("ports", "1-1024")
        verify = request.form.get("verify") == "on"

        # 后台线程执行扫描
        thread = threading.Thread(target=run_scan)
        thread.start()

        flash("扫描已启动", "success")
        return redirect(url_for("views.history"))

    return render_template("new_scan.html")
```

**表单字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `target` | text | 扫描目标（IP/CIDR/范围） |
| `method` | select | 发现方式（icmp/arp/syn/all） |
| `ports` | text | 端口范围（如 1-1024） |
| `verify` | checkbox | 启用主动验证 |

### 2.4 扫描详情 (Scan Detail)

```python
# web/views.py:200-252

@views_bp.route("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    """扫描详情页面"""
    # 获取扫描数据
    scan = scan_repo.get(scan_id)
    hosts = host_repo.get_by_scan(scan_id)
    risk_results = risk_repo.get_by_scan(scan_id)

    # 构建主机-服务-漏洞映射
    host_data = []
    for host in hosts:
        services = service_repo.get_by_host(host.id)
        risk = risk_map.get(host.id)
        host_data.append({...})

    # 计算风险摘要
    summary = calculate_scan_risk_summary(risk_results)

    return render_template("scan_detail.html", ...)
```

**页面内容**：
- 扫描摘要（目标、时间、状态）
- 主机列表（IP、风险评分、漏洞数）
- 服务详情（端口、协议、产品版本）
- 漏洞列表（CVE、CVSS、描述）
- 风险分布饼图
- 报告导出按钮

### 2.5 网络拓扑 (Topology)

```python
# web/views.py:255-267

@views_bp.route("/scans/<int:scan_id>/topology")
def topology(scan_id: int):
    """网络拓扑可视化页面"""
    scan = scan_repo.get(scan_id)
    return render_template("topology.html", scan=scan)
```

**页面特性**：
- ECharts 力导向图
- 节点颜色表示风险等级
- 节点大小表示风险评分
- 支持拖拽和缩放
- 悬停显示主机详情

### 2.6 扫描对比 (Compare)

```python
# web/views.py:281-348

@views_bp.route("/compare/<int:scan_id_old>/<int:scan_id_new>")
def compare(scan_id_old: int, scan_id_new: int):
    """扫描对比页面"""
    comparator = ScanComparator()
    diff = comparator.compare(
        scan_old, scan_new,
        hosts_old, hosts_new,
        services_old, services_new,
        vulns_old, vulns_new,
        risks_old, risks_new,
    )

    return render_template("compare.html", diff=diff)
```

**对比内容**：
- 新增/移除的主机
- 新增/移除的服务
- 新增/修复的漏洞
- 风险变化趋势

---

## 3. REST API (api.py)

### 3.1 API 总览

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/trends` | GET | 获取安全趋势数据 |
| `/api/scans` | GET | 列出所有扫描 |
| `/api/scans` | POST | 启动新扫描 |
| `/api/scans/<id>` | GET | 获取扫描详情 |
| `/api/scans/<id>/topology` | GET | 获取网络拓扑数据 |
| `/api/scans/<id>/remediation` | GET | 获取修复建议 |
| `/api/scans/<id>/report` | GET | 生成/下载报告 |

### 3.2 获取安全趋势

```
GET /api/trends?days=30
```

**参数**：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `days` | int | 30 | 时间范围（7-365 天） |

**响应**：

```json
{
  "dates": ["2024-01-01", "2024-01-02", ...],
  "scan_counts": [1, 2, 1, ...],
  "host_counts": [5, 8, 6, ...],
  "vuln_counts": [12, 15, 10, ...],
  "risk_scores": [45.2, 52.1, 38.5, ...]
}
```

### 3.3 列出所有扫描

```
GET /api/scans
```

**响应**：

```json
{
  "scans": [
    {
      "id": 1,
      "target_range": "192.168.1.0/24",
      "status": "completed",
      "started_at": "2024-01-15T10:30:00",
      "finished_at": "2024-01-15T10:35:00"
    },
    ...
  ]
}
```

### 3.4 启动新扫描

```
POST /api/scans
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "method": "icmp",
  "ports": "1-1024"
}
```

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `target` | string | 是 | 扫描目标 |
| `method` | string | 否 | 发现方式（默认 icmp） |
| `ports` | string | 否 | 端口范围（默认 1-1024） |

**响应**：

```json
{
  "message": "Scan started",
  "target": "192.168.1.0/24",
  "method": "icmp"
}
```

**状态码**：`202 Accepted`（扫描在后台执行）

### 3.5 获取扫描详情

```
GET /api/scans/1
```

**响应**：

```json
{
  "scan": {
    "id": 1,
    "target_range": "192.168.1.0/24",
    "status": "completed",
    "started_at": "2024-01-15T10:30:00",
    "finished_at": "2024-01-15T10:35:00"
  },
  "hosts": [
    {
      "id": 1,
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "os_guess": "Linux 4.x",
      "mac": "00:11:22:33:44:55",
      "services": [
        {
          "port": 22,
          "proto": "tcp",
          "service_name": "ssh",
          "product": "OpenSSH",
          "version": "8.2p1"
        }
      ],
      "risk_score": 45.2,
      "risk_level": "High",
      "vuln_count": 5
    }
  ],
  "summary": {
    "total_hosts": 7,
    "total_vulns": 50,
    "critical_vulns": 3,
    "high_vulns": 12,
    "medium_vulns": 20,
    "low_vulns": 15
  }
}
```

### 3.6 获取网络拓扑

```
GET /api/scans/1/topology
```

**响应**：

```json
{
  "backgroundColor": "#161B22",
  "tooltip": {"trigger": "item"},
  "series": [{
    "type": "graph",
    "layout": "force",
    "data": [
      {
        "name": "192.168.1.1",
        "value": 45.2,
        "symbolSize": 39,
        "itemStyle": {"color": "#DB6D28"}
      }
    ],
    "links": [
      {
        "source": "192.168.1.1",
        "target": "192.168.1.2",
        "lineStyle": {"color": "#30363D"}
      }
    ],
    "roam": true,
    "draggable": true,
    "force": {
      "repulsion": 300,
      "edgeLength": [80, 150]
    }
  }]
}
```

**用法**：直接传递给 ECharts 的 `setOption()` 方法。

### 3.7 获取修复建议

```
GET /api/scans/1/remediation
```

**响应**：

```json
{
  "total": 15,
  "critical_count": 3,
  "high_count": 5,
  "medium_count": 4,
  "low_count": 3,
  "by_priority": {
    "critical": [
      {
        "title": "修复 CVE-2021-44228: Log4j RCE",
        "action": "升级 Log4j 至 2.17.0 或更高版本",
        "priority": "critical",
        "reference": "https://logging.apache.org/log4j/2.x/security.html"
      }
    ],
    "high": [...],
    "medium": [...],
    "low": [...]
  }
}
```

### 3.8 生成报告

```
GET /api/scans/1/report?format=pdf
```

**参数**：

| 参数 | 类型 | 默认值 | 可选值 |
|------|------|--------|--------|
| `format` | string | html | html, pdf, json |

**响应**：

| 格式 | Content-Type | 说明 |
|------|-------------|------|
| `html` | text/html | HTML 报告内容 |
| `pdf` | application/pdf | PDF 文件下载 |
| `json` | application/json | 结构化数据 |

---

## 4. 国际化支持

Web 界面支持中英文切换：

```python
# web/views.py:27-102

I18N = {
    "zh_CN": {
        "dashboard": "仪表盘",
        "new_scan": "新建扫描",
        "scan_history": "扫描历史",
        "target": "扫描目标",
        "start_scan": "开始扫描",
        ...
    },
    "en_US": {
        "dashboard": "Dashboard",
        "new_scan": "New Scan",
        "scan_history": "Scan History",
        "target": "Target",
        "start_scan": "Start Scan",
        ...
    },
}
```

通过配置 `LANGUAGE` 切换语言：

```python
app.config["LANGUAGE"] = "en_US"
```

---

## 5. 安全特性

### 5.1 CSRF 保护

所有 POST 请求需要 CSRF 令牌：

```html
<form method="post">
    {{ csrf_token() }}
    <!-- 表单字段 -->
</form>
```

### 5.2 API 调用示例

```bash
# 使用 curl 调用 API
curl -X GET http://localhost:5000/api/scans

# 启动扫描（需要 CSRF 令牌或禁用检查）
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24"}'
```

---

## 6. 前端集成

### 6.1 加载趋势图

```javascript
// 页面加载时获取趋势数据
fetch('/api/trends?days=30')
  .then(res => res.json())
  .then(data => {
    // 使用 ECharts 渲染图表
    const chart = echarts.init(document.getElementById('trend-chart'));
    chart.setOption({
      xAxis: { data: data.dates },
      series: [
        { name: '漏洞数', data: data.vuln_counts }
      ]
    });
  });
```

### 6.2 加载拓扑图

```javascript
// 获取拓扑数据并渲染
fetch(`/api/scans/${scanId}/topology`)
  .then(res => res.json())
  .then(option => {
    const chart = echarts.init(document.getElementById('topology'));
    chart.setOption(option);  // 直接使用返回的配置
  });
```

---

## 7. 代码位置速查

| 功能 | 文件 | 关键代码 |
|------|------|----------|
| 应用工厂 | `web/app.py` | `create_app()` |
| 仪表盘页面 | `web/views.py` | `dashboard()` |
| 新建扫描页面 | `web/views.py` | `new_scan()` |
| 扫描详情页面 | `web/views.py` | `scan_detail()` |
| 拓扑页面 | `web/views.py` | `topology()` |
| 扫描历史页面 | `web/views.py` | `history()` |
| 扫描对比页面 | `web/views.py` | `compare()` |
| 趋势 API | `web/api.py` | `get_trends()` |
| 扫描列表 API | `web/api.py` | `list_scans()` |
| 启动扫描 API | `web/api.py` | `start_scan()` |
| 扫描详情 API | `web/api.py` | `get_scan()` |
| 拓扑数据 API | `web/api.py` | `get_topology()` |
| 修复建议 API | `web/api.py` | `get_remediation()` |
| 报告生成 API | `web/api.py` | `generate_report()` |

---

## 下一步

- [CLI 命令行接口](cli.md) - 了解命令行使用方式
- [报告生成模块](../modules/07_reporting.md) - 了解报告生成原理
- [快速上手教程](../tutorials/quick_start.md) - 实践操作指南
