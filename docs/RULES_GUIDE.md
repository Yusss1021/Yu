# 规则库（Rules）入门指南

适用人群：零基础，想自己维护或导入漏洞规则的人。

本项目是 offline-first：不强依赖在线 NVD。规则以本地 JSON 的形式保存，便于审计、复现和离线使用。

## 1. 什么是“规则”

这里的“规则”就是一条可读的匹配条件。

当扫描识别到某个服务（service）、产品（product）、端口（port）和版本（version）时，如果满足 `version_rule`，系统就认为“可能存在某个 CVE”，并生成一条漏洞发现记录。

为什么用本地 JSON：
- 离线也能跑，不会被外网限制卡住
- 规则可控，可复现，实验数据更稳定
- 格式简单，手工写和批量生成都方便

## 2. 规则文件在哪

默认规则库文件：`vuln_assessor/vuln/rules.json`

规则管理命令会把输入做一次“标准化”后再落盘，比如：
- `cve_id` 自动转大写
- `service`/`product` 自动转小写
- `cvss` 会被限制在 0 到 10，并保留 1 位小数
- `port` 不是整数会变成 `null`
- `version_rule` 为空会当成 `*`

## 3. JSON 结构（最小示例）

规则库是一个 JSON 列表，每个元素是一条规则对象：

```json
[
  {
    "cve_id": "CVE-2021-41773",
    "service": "http",
    "product": "apache httpd",
    "port": 80,
    "version_rule": "2.4.49-2.4.50",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "description": "Apache HTTP Server 路径遍历与潜在远程代码执行漏洞。",
    "remediation": "升级 Apache HTTP Server 至 2.4.51 及以上。",
    "exploit_maturity": 9.0,
    "asset_criticality": 5.0
  }
]
```

## 4. 字段解释（按代码支持的口径）

| 字段 | 类型 | 作用 | 取值建议/细节 |
| --- | --- | --- | --- |
| cve_id | string | 漏洞编号 | 必填，如 `CVE-2021-41773` |
| service | string | 服务名匹配 | 小写，做“包含匹配”，如 `http` 会匹配 `http-proxy` |
| product | string | 产品名匹配 | 小写，做“包含匹配”，如 `apache` 可匹配 `apache httpd` |
| port | int or null | 端口约束 | `null` 表示不限制端口；填整数会精确匹配 |
| version_rule | string | 版本规则 | 见下文语法；空或 `*` 表示任意版本 |
| severity | string | 严重等级 | 仅支持 `CRITICAL/HIGH/MEDIUM/LOW`，其他会回落为 `MEDIUM` |
| cvss | number | CVSS 基础分 | 0 到 10，会被夹紧并保留 1 位小数 |
| description | string | 漏洞描述 | 可为空，但建议写清楚“影响是什么” |
| remediation | string | 修复建议 | 可为空，但建议写清楚“怎么做” |
| exploit_maturity | number | 可利用性分 | 0 到 10，缺省时会按 severity 给默认值（CRITICAL=9.0, HIGH=8.0, MEDIUM=6.0, LOW=3.5） |
| asset_criticality | number | 资产重要性分 | 0 到 10，默认 5.0；也可在扫描时用资产画像覆盖 |

只要 `service` 或 `product` 至少有一个不为空，这条规则才会被认为是有效规则。

## 5. 匹配是怎么发生的（直观版）

一条规则要命中某个被识别的服务指纹，顺序大致是：
1. `service` 和 `product` 做包含匹配（不区分大小写）
2. `port` 为 `null` 则不限制，否则需要端口相等
3. `version_rule` 为 `*` 则直接通过
4. `version_rule` 不是 `*` 时，需要版本比较通过，或者触发“版本缺失”兜底逻辑（见第 8 节）

## 6. version_rule 语法（只支持这些）

系统只做“数字版本”比较，会从版本字符串里提取数字（最多取前 4 段）。比如 `OpenSSH_8.8p1` 会被当成 `8.8.1` 来比较。

支持的写法：

1) 通配
- `*` 或空字符串：任何版本都算匹配

2) 单条件比较（比较符 + 版本号）
- `<=8.8`
- `>=1.0`
- `==2.4.49`
- `<9.0.54`

3) 多条件比较（逗号分隔，表示同时满足）
- `>=1.0,<2.0`
- `>3.0,<=3.0.3`

4) 区间（用 `-`，且规则里不能出现 `<`、`>`、`==`）
- `2.4.49-2.4.50` 表示包含两端的闭区间

写规则时可以带空格，系统会自动忽略空格。

## 7. match_confidence 和置信度等级怎么用

每条命中都会带一个 `match_confidence`，范围 0 到 10。这个分数更像“指纹信息完整度”得分，不是 CVSS，也不是“漏洞一定存在”的概率。

置信度等级（阈值写死在代码里）：
- HIGH：`match_confidence >= 7.5`
- MEDIUM：`match_confidence >= 5.0`
- LOW：其他情况

这个等级会影响两件事：
1. 风险评分里会把 `match_confidence` 作为一个加权因子（权重 0.10）
2. 输出里会给出是否需要人工确认的建议（LOW 必须确认，MEDIUM 建议确认，HIGH 一般不需要）

## 8. 版本缺失时为什么会强制 LOW

如果扫描结果里版本是空字符串，同时规则的 `version_rule` 不是 `*`，系统会把这条命中当成“只根据 service/product/port 推断”，并执行两条硬规则：
- `match_confidence` 会被上限限制到 `4.5`
- `confidence_tier` 会被强制为 `LOW`，并标记 `manual_confirmation_needed = True`

这不是 bug。它是在提醒你：缺版本时很容易误报，需要你再去确认真实版本。

## 9. 用 CLI 管理规则库（复制即可）

查看规则统计：

```bash
python3 main.py rules list --db data/scans.db
```

从本地文件导入（merge 合并，replace 覆盖）：

```bash
python3 main.py rules import --input docs/rules_feed.example.json --mode merge --db data/scans.db
```

从 URL 更新：

```bash
python3 main.py rules update --url <url> --mode merge --db data/scans.db
```

SSRF 风险提示：`rules update` 会从你提供的 URL 拉取 JSON，如果这个 URL 来自不可信输入，攻击者可能借机让你的机器去访问内网地址或云平台元数据接口，从而造成信息泄露或内网探测。只对可信、可控的地址使用它，最好做域名或 IP 白名单限制，不要把该功能暴露给未授权用户。

兼容写法（当前实现实际使用的是 `--rules-file`，而不是 `--db`）：

```bash
python3 main.py rules list --rules-file vuln_assessor/vuln/rules.json
python3 main.py rules import --input docs/rules_feed.example.json --mode merge --rules-file vuln_assessor/vuln/rules.json
python3 main.py rules update --url <url> --mode merge --rules-file vuln_assessor/vuln/rules.json
```

## 10. 写规则时的几个小建议

- service/product 是“包含匹配”，写得越泛，误报越多。能写具体就别太宽。
- http/https 这类常见服务，建议配合 `product` 或 `port` 缩小范围。
- 想让版本规则生效，就要尽量让扫描能拿到版本。缺版本时系统会主动降低置信度并提示手动确认。
